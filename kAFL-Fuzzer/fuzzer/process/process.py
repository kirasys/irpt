
import os
from   pprint import pformat
import json
import mmh3
import time
import struct

from common.debug import log_process
from common.util import print_warning, print_fail, print_note, p32
from common.execution_result import ExecutionResult
from common.qemu import qemu
from common.wdm import ProgramOptimizer, ProgramDatabase, IRP
from fuzzer.statistics import MasterStatistics
from fuzzer.bitmap import BitmapStorage
from fuzzer.technique import bitflip, arithmetic, interesting_values

u32 = lambda x : struct.unpack('<I', x)[0]

class Process:

    def __init__(self, config, pid=0):
        self.config = config
        self.debug_mode = config.argument_values['debug']
        self.task_count = 0
        self.task_paused = False

        self.busy_events = 0
        self.empty_hash = mmh3.hash(("\x00" * self.config.config_values['BITMAP_SHM_SIZE']), signed=False)

        self.statistics = MasterStatistics(self.config)
        self.bitmap_storage = BitmapStorage(config, config.config_values['BITMAP_SHM_SIZE'], "process", read_only=False)

        log_process("Starting (pid: %d)" % os.getpid())
        log_process("Configuration dump:\n%s" %
                pformat(config.argument_values, indent=4, compact=True))

        self.q = qemu(pid, self.config,
                      debug_mode=config.argument_values['debug'])
        self.programOptimizer = ProgramOptimizer(self.q)
        self.programDB = ProgramDatabase(config.argument_values['wdm']) # load interface
        #self.progs = ProgQueue(self.config, self.statistics)

    def maybe_insert_program(self, program, exec_res):
        bitmap_array = exec_res.copy_to_array()
        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array, exec_res.exit_reason,
                                                       exec_res.performance)
        bitmap.lut_applied = True  # since we received the bitmap from the should_send_to_master, the lut was already applied
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)
        if should_store and not exec_res.is_crash():
            self.programOptimizer.add(program, bitmap, new_bytes, new_bits)

    def execute_irp(self, index):
        """
        Send IRP to qemu agent and receive a coverage.
        returns True if qemu has crashed.
        """
        # send irp request.
        irp = self.cur_program.irps[index]
        exec_res = self.q.send_irp(irp)
        is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
        crash = exec_res.is_crash()

        if is_new_input:
            new_program = self.cur_program.clone_with_interface(self.cur_program.irps[:index+1])
            self.maybe_insert_program(new_program, exec_res)
        else:
            log_process("Crashing input found (%s), but not new (discarding)" % (exec_res.exit_reason))

        # restart Qemu on crash
        if crash:
            #self.statistics.event_reload()
            print("[+] Crash found!")
            self.q.reload()
            return True
        
        return False

    def execute(self, program):
        self.cur_program = program
        self.q.revert_driver()

        for i in range(len(self.cur_program.irps)):
            if self.execute_irp(i):
                return

    def execute_deterministic(self, program):
        self.cur_program = program

        irps = self.cur_program.irps
        for index in range(len(irps)):
            self.q.revert_driver()
            for j in range(index):
                self.q.send_irp(irps[j])

            # deterministic logic
            # Walking bitfilps
            if bitflip.mutate_seq_walking_bits(index, self): 
                return
            if bitflip.mutate_seq_two_walking_bits(index, self): 
                return
            if bitflip.mutate_seq_four_walking_bits(index, self): 
                return

            # Walking byte sets
            if bitflip.mutate_seq_walking_byte(index, self):
                return
            if bitflip.mutate_seq_two_walking_bytes(index, self):
                return
            if bitflip.mutate_seq_four_walking_bytes(index, self):
                return

            # Arithmetic mutations
            if arithmetic.mutate_seq_8_bit_arithmetic(index, self):
                return
            if arithmetic.mutate_seq_16_bit_arithmetic(index, self):
                return
            if arithmetic.mutate_seq_32_bit_arithmetic(index, self):
                return

            # Interesting value mutations
            if interesting_values.mutate_seq_8_bit_interesting(index, self):
                return
            if interesting_values.mutate_seq_16_bit_interesting(index, self):
                return
            if interesting_values.mutate_seq_32_bit_interesting(index, self):
                return
    
    def loop(self):
        if not self.q.start():
            return

        program = self.programDB.getInput()
        self.execute(program)
        self.programOptimizer.clear()   # Default code coverage.
            
        while True:
            program = self.programDB.getInput()
            
            for _ in range(10):
                program.mutate(self.programDB.programs)
                self.execute(program)
                
                while self.programOptimizer.optimizable():
                    new_programs = list(self.programOptimizer.optimize())
                    self.programOptimizer.clear()
                    if new_programs:
                        log_process("[+] New interesting program found.")
                        self.programDB.add(new_programs)
                        
                        # start deterministic execution.
                        for p in new_programs:
                            p.dump()
                            print("Start deterministic execution.")
                            self.execute_deterministic(p)
                            print("End deterministic execution.")
                            
                
    def shutdown(self):
        self.q.shutdown()



