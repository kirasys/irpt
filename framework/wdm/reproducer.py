#!/usr/bin/env python3
#
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import copy
from debug.log import log
from wdm.program import Program
from common.config import default_config

class Reproducer:
    def __init__(self, q, statistics):
        self.q = q
        self.repro_queue = []
        self.statistics = statistics

        self.crash_map = [0] * (default_config['COVERAGE_MAP_SHM_SIZE'] // 2)
        
    def clear(self):
        self.repro_queue = []

    def add(self, program):
        self.repro_queue.append(copy.deepcopy(program))

    def reproducible(self):
        return len(self.repro_queue) > 0

    def reproduce(self):
        self.q.enable_coverage_map()
        for program in self.repro_queue:
            self.q.reload_driver()

            for i in range(len(program.irps)):
                exec_res = self.q.send_irp(program.irps[i])

                if exec_res.is_crash():
                    log("[*] %s found!!" % exec_res.exit_reason, "CRASH")
                    self.q.reload()
                    self.statistics.event_reload()

                    unique = True
                    for address in exec_res.coverage_to_array():
                        if self.crash_map[address]:
                            unique = False
                        self.crash_map[address] = True
                    

                    if unique and not exec_res.is_timeout(): # unique crash
                        program.save_to_file('unique_crash')
                        self.statistics.event_unique_findings(exec_res.exit_reason)
                    else:
                        program.save_to_file(exec_res.exit_reason)
                    self.statistics.event_findings(exec_res.exit_reason)
                    break
                
        self.q.disable_coverage_map()
        self.clear()