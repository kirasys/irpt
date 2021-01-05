# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Manage status outputs for Master and Slave instances
"""

import msgpack
import time

from common.util import atomic_write, read_binary_file

class ProcessStatistics:
    def __init__(self, config):
        self.config = config
        self.execs_last = 0
        self.execs_time = 0
        self.plot_last = 0
        self.plot_thres = 5
        self.write_last = 0
        self.write_thres = 0.5
        self.work_dir = self.config.argument_values['work_dir']
        self.data = {
                "start_time": time.time(),
                "run_time": 0, 
                "total_execs": 0,
                "num_funky": 0,
                "num_reload": 0,
                "paths_total": 0,
                "paths_pending": 0,
                "favs_pending": 0,
                "favs_total": 0,
                "max_level": 0,
                "cycles": 0,
                "bytes_in_bitmap": 0,
                "yield": {
                    "initial" : 0,
                    "pagefault" : 0,
                    "dependency" : 0,
                    "seq_walking_bit": 0,
                    "seq_two_walking_bits": 0,
                    "seq_four_walking_bits": 0, 
                    "seq_walking_byte": 0,
                    "seq_two_walking_bytes" : 0,
                    "seq_four_walking_bytes" : 0,
                    "seq_8bits_arithmetic" : 0,
                    "seq_16bits_arithmetic" : 0,
                    "seq_32bits_arithmetic" : 0,
                    "seq_8bits_interesting" : 0,
                    "seq_16bits_interesting" : 0,
                    "seq_32bits_interesting" : 0,
                    "seq_8bits_rand8bit" : 0,
                    "seq_16bits_rand16bit" : 0,
                    "seq_32bits_rand16bit" : 0,
                    "seq_32bits_rand32bit" : 0,
                    "seq_64bits_rand8bit" : 0,
                    "mutate_buffer_length" : 0,
                    "bruteforce_irps" : 0
                },
                "stage": {
                    "initial" : 0,
                    "pagefault" : 0,
                    "dependency" : 0,
                    "seq_walking_bit": 0,
                    "seq_two_walking_bits": 0,
                    "seq_four_walking_bits": 0, 
                    "seq_walking_byte": 0,
                    "seq_two_walking_bytes" : 0,
                    "seq_four_walking_bytes" : 0,
                    "seq_8bits_arithmetic" : 0,
                    "seq_16bits_arithmetic" : 0,
                    "seq_32bits_arithmetic" : 0,
                    "seq_8bits_interesting" : 0,
                    "seq_16bits_interesting" : 0,
                    "seq_32bits_interesting" : 0,
                    "seq_8bits_rand8bit" : 0,
                    "seq_16bits_rand16bit" : 0,
                    "seq_32bits_rand16bit" : 0,
                    "seq_32bits_rand32bit" : 0,
                    "seq_64bits_rand8bit" : 0,
                    "mutate_buffer_length" : 0,
                    "bruteforce_irps" : 0
                },
                "findings": {
                    "regular": 0,
                    "crash": 0,
                    "timeout": 0,
                },
                "unique_findings": {
                    "crash": 0,
                    "timeout": 0,
            },
                "now_program_id": 0,
                "new_edges_on": None
                }

    def event_database_cycle(self, program):
        self.data["cycles"] += 1
        self.data["now_program_id"] = program.get_id()

        if program.is_initial():
            program.unset_initial()
            self.data["paths_pending"] -= 1

    def event_program_new(self, program): # TODO:
        self.update_yield(program.get_state())
        self.data["findings"]['regular'] += 1

        program.set_initial()
        self.data["paths_total"] += 1
        self.data["paths_pending"] += 1

        self.data["new_edges_on"] = program.get_parent_id()
        self.data["bytes_in_bitmap"] += len(program.get_new_bytes())
        self.data["max_level"] = max(program.get_level(), self.data["max_level"])

    def event_findings(self, exit_reason):
        self.data["findings"][exit_reason] += 1

    def event_unique_findings(self, exit_reason):
        self.event_findings(exit_reason)
        self.data["unique_findings"][exit_reason] += 1

    def update_yield(self, method):
        if method not in self.data["yield"]:
            self.data["yield"][method] = 0
        self.data["yield"][method] += 1

    def event_exec(self, now_trying):
        self.data["total_execs"] += 1
        self.data["stage"][now_trying] += 1

    def event_reload(self):
        self.data["num_reload"] += 1
        
    def event_funky(self):
        self.data["num_funky"] += 1

    def get_total_execs(self):
        return self.data["total_execs"]