
import os
import sys
from   pprint import pformat
import json
import time
import copy
import struct
import threading

from debug.log import log

from common import rand
from common.qemu import qemu
from common.debug import log_process
from common.util import print_warning, print_fail, print_note, p32
from common.execution_result import ExecutionResult

from wdm.irp import IRP
from wdm.program import Program
from wdm.optimizer import Optimizer
from wdm.database import Database
from wdm.reproducer import Reproducer
from wdm.interface import interface_manager
from fuzzer.statistics import ProcessStatistics
from fuzzer.bitmap import BitmapStorage
from fuzzer.technique import bitflip, arithmetic, interesting_values, havoc, wdmstyle

u32 = lambda x : struct.unpack('<I', x)[0]

class Process:

    def __init__(self, config, pid=0):
        self.config = config
        self.debug_mode = config.argument_values['debug']

        self.statistics = ProcessStatistics(self.config)
        self.bitmap_storage = BitmapStorage(config, config.config_values['BITMAP_SHM_SIZE'], "process", read_only=False)

        log_process("Starting (pid: %d)" % os.getpid())
        log_process("Configuration dump:\n%s" %
                pformat(config.argument_values, indent=4, compact=True))

        self.q = qemu(pid, self.config,
                      debug_mode=self.debug_mode)
        self.optimizer = Optimizer(self.q, self.statistics)
        self.reproducer = Reproducer(self.q, self.statistics)
        self.database = Database(self.statistics) # load interface

    def __set_current_program(self, program):
        self.cur_program = program

    def maybe_insert_program(self, program, exec_res):
        bitmap_array = exec_res.copy_to_array()
        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array, exec_res.exit_reason,
                                                       exec_res.performance)
        bitmap.lut_applied = True  # since we received the bitmap from the should_send_to_master, the lut was already applied
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)
        if should_store and not exec_res.is_crash():
            program.set_new_bits(new_bits)
            program.set_new_bytes(new_bytes)
            self.optimizer.add(program, bitmap, new_bytes, new_bits)

    def execute_irp(self, index):
        """
        Send IRP to qemu agent and receive a coverage.
        returns True if qemu has crashed.
        """
        # send irp request.
        irp = self.cur_program.irps[index]
        exec_res = self.q.send_irp(irp)
        self.statistics.event_exec(self.cur_program.get_state())
    
        is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
        if is_new_input:
            new_program = self.cur_program.clone_with_irps(self.cur_program.irps[:index+1])
            self.maybe_insert_program(new_program, exec_res)

        # restart Qemu on crash
        if exec_res.is_crash():
            if exec_res.is_timeout():
                log("Timeouted maybe? (%x)" % irp.IoControlCode, "CRASH")
            else:
                log("Crashed maybe? (%x)" % irp.IoControlCode, "CRASH")
                self.cur_program.save_to_file("unreproduced")

            self.q.reload()
            self.statistics.event_reload()
            self.reproducer.add(self.cur_program.clone_with_irps(self.cur_program.irps[:index+1]))
            return True
        return False

    def execute_program(self, program):
        self.__set_current_program(program)
        self.q.reload_driver()

        for i in range(len(self.cur_program.irps)):
            if self.execute_irp(i):
                return True
    
    def __execute_dependency(self, length):
        self.q.reload_driver()
        for i in range(length):
            exec_res = self.q.send_irp(self.cur_program.irps[i])
            if exec_res.is_crash():
                return True

    def execute_deterministic(self, program):
        self.__set_current_program(program)
        
        irps = self.cur_program.irps
        for index in range(len(irps)):
            if irps[index].InBufferLength == 0:
                continue

            # deterministic logic
            # Walking bitfilps
            if self.__execute_dependency(index) or bitflip.mutate_seq_walking_bit(self, index): 
                return
            if bitflip.mutate_seq_two_walking_bits(self, index): 
                return
            if bitflip.mutate_seq_four_walking_bits(self, index): 
                return
            
            # Walking byte sets
            if bitflip.mutate_seq_walking_byte(self, index):
                return
            if bitflip.mutate_seq_two_walking_bytes(self, index):
                return
            if bitflip.mutate_seq_four_walking_bytes(self, index):
                return

            # Arithmetic mutations
            if arithmetic.mutate_seq_8_bit_arithmetic(self, index):
                return
            if arithmetic.mutate_seq_16_bit_arithmetic(self, index):
                return
            if arithmetic.mutate_seq_32_bit_arithmetic(self, index):
                return

            # Interesting value mutations
            if interesting_values.mutate_seq_8_bit_interesting(self, index):
                return
            if interesting_values.mutate_seq_16_bit_interesting(self, index):
                return
            if interesting_values.mutate_seq_32_bit_interesting(self, index):
                return
            
            # Scan non paged area fault.
            if wdmstyle.scan_page_fault(self, index):
                return
        
        # Resolve IOCTL dependency.
        if wdmstyle.resolve_dependency(self):
            return
        
        self.cur_program.set_dirty(False)

    def execute_havoc(self, program):
        self.__set_current_program(program)

        irps = self.cur_program.irps
        for index in range(len(irps)):
            if irps[index].InBufferLength == 0:
                continue

            # Random value mutations
            if self.__execute_dependency(index) or havoc.mutate_seq_8_bit_rand8bit(self, index):
                return
            if havoc.mutate_seq_16_bit_rand16bit(self, index):
                return
            if havoc.mutate_seq_32_bit_rand32bit(self, index):
                return
            if havoc.mutate_seq_32_bit_rand16bit(self, index):
                return
            if havoc.mutate_seq_64_bit_rand8bit(self, index):
                return
            
            # InBufferLength mutation
            if havoc.mutate_buffer_length(self, index):
                return
        
        if havoc.bruteforce_irps(self):
            return  

    def loop(self):
        # Start the QEMU
        if not self.q.start():
            return

        # Start logging.
        t = threading.Thread(target=self.log_current_state, args=())
        t.start()

        # basic coverage program.
        program = self.database.get_next()
        self.execute_program(program)
        
        program.irps = program.irps[::-1]
        self.execute_program(program)

        while self.optimizer.optimizable():
            new_programs = self.optimizer.optimize()
            self.database.add(new_programs)
            
        # Import seeds.
        seed_directory = self.config.argument_values['seed_dir']
        if len(os.listdir(seed_directory)):
            for (directory, _, files) in os.walk(seed_directory):
                for f in files:
                    path = os.path.join(directory, f)
                    log("Importing seed (%s)" % path)
                    if os.path.exists(path):
                        program = Program()
                        program.load(path)
                        # If a crash(or timeout) occurs, retry an execution.
                        while True:
                            if not self.execute_program(program):
                                log("[!] Imported seed crashed!")
                                break
                            self.reproducer.clear()
                            self.optimizer.clear()
                        
                        while self.optimizer.optimizable():
                            new_programs = self.optimizer.optimize()
                            if new_programs:
                                self.database.add(new_programs)
        
        log("[+] Count of initial unique programs  : %d" % len(self.database.unique_programs))
        if interface_manager.count() != len(self.database.unique_programs):
            log("[!] Some IOCTL code were ignored maybe")

        while True:
            program = self.database.get_next()
            programCopyed = copy.deepcopy(program)

            for _ in range(1):
                programCopyed.mutate(corpus_programs=self.database.get_programs())

                # Execution
                if programCopyed.get_dirty():
                    self.execute_deterministic(programCopyed)
                else:
                    self.execute_havoc(programCopyed)

                # Get new interesting corpus
                while self.optimizer.optimizable():
                    new_programs = self.optimizer.optimize()
                    if new_programs:
                        self.database.add(new_programs)
                        
                        # Start deterministic execution.
                        for prog in new_programs:
                            prog.set_state("AFLdetermin")
                            self.execute_deterministic(copy.deepcopy(prog))
                
                # crash reproduction
                self.reproducer.reproduce()

            # synchronization
            program.program_struct["dirty"] = programCopyed.program_struct["dirty"]
            program.program_struct["exec_count"] = programCopyed.program_struct["exec_count"]
            
            # Update update_probability_map of the corpus database.
            self.database.update_probability_map()

    def log_current_state(self):
        while True:
            time.sleep(3)
            log('', label='')
            log("---- Corpus Database -----" )
            self.database.dump()
            log("---- Current state (id=%d) ----" % self.cur_program.get_id())
            log("exec_speed=%ds, state=%s" % (self.statistics.data["total_execs"] / (time.time() - self.statistics.data["start_time"]), self.cur_program.get_state()))
            log("total_paths=%d, unique=%d, pending=%d" % (self.statistics.data["paths_total"], len(self.database.get_unique_programs()), self.statistics.data["paths_pending"]))
            log("total_crash=%d, unique=%d, timeout=%d" % (self.statistics.data["findings"]["crash"], self.statistics.data['unique_findings']['crash'], self.statistics.data["findings"]["timeout"]))

    def shutdown(self):
        self.q.shutdown()