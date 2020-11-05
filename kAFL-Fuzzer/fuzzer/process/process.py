
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

    def execute(self, program):
        score = 1
        irps = program.irps
        for i in range(len(irps)):
            exec_res = self.q.send_irp(irps[i])
            is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
            crash = exec_res.is_crash()

            if is_new_input:
                new_program = program.clone_with_interface(irps[:i+1])
                self.maybe_insert_program(new_program, exec_res)
                score += 100
            else:
                log_process("Crashing input found (%s), but not new (discarding)" % (exec_res.exit_reason))

            # restart Qemu on crash
            if crash:
                #self.statistics.event_reload()
                print("[+] Crash found!")
                self.q.reload()
        
        return score
                
    def loop(self):
        if not self.q.start():
            return

        program = self.programDB.getInput()
        self.execute(program)
        self.programOptimizer.clear()   # Default code coverage.
            
        while True:
            program = self.programDB.getInput()
            
            hp = 10
            while hp > 0:
                program.mutate(self.programDB.programs)
                hp -= self.execute(program)
                
                if self.programOptimizer.optimizable():
                    log_process("[+] New interesting program found. (Start optimizer)")
                    self.programDB.add(list(self.programOptimizer.optimize()))
                else:
                    self.q.revert_driver()
                
    def shutdown(self):
        self.q.shutdown()



