import copy

from debug.log import log
from wdm.program import Program

class Crasher:
    def __init__(self, q, statistics):
        self.q = q
        self.statistics = statistics
        self.crasher_queue = []

    def clear(self):
        self.crasher_queue = []

    def add(self, program):
        self.crasher_queue.append(copy.deepcopy(program))

    def reproduce(self):
        for program in self.crasher_queue:
            self.q.reload_driver()
            for i in range(len(program.irps)):
                exec_res = self.q.send_irp(program.irps[i])
                if exec_res.is_crash():
                    if exec_res.is_timeout():
                        log("[*] Timeout found!!", "CRASH")
                        program.program_struct["info"]["exit_reason"] = 'timeout'
                    else:
                        log("[*] Crash found!!", "CRASH")
                        program.program_struct["info"]["exit_reason"] = 'crash'
                    self.q.reload()
                    program.save_to_file(exec_res.exit_reason)
                    self.statistics.event_program_new(program)
                    self.statistics.event_program_unique(program)
                    program.update_metadata()
                    Program.NextID += 1
                    break
        
        self.clear()