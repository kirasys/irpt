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
        self.num_slaves = self.config.argument_values['p']
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
                    "insertIRP": 0,
                    "swapIRP": 0, 
                    "mutateArg": 0,
                    "AFLdetermin" : 0,
                    "splice" : 0
                },
                "stage": {
                    "initial" : 0,
                    "insertIRP": 0,
                    "swapIRP": 0, 
                    "mutateArg": 0,
                    "AFLdetermin" : 0,
                    "splice" : 0
                },
                "findings": {
                    "regular": 0,
                    "crash": 0,
                    "kasan": 0,
                    "timeout": 0,
                },
                "unique_findings": {
                    "crash": 0,
                    "kasan": 0,
                    "timeout": 0,
                },
                "num_slaves": self.num_slaves,
                "now_program_id": 0,
                "programs" : 0,
                "unique_programs" : 0,
                "now_trying": "initial",
                "new_edges_on": None
                }

        self.stats_file = self.work_dir + "/stats"
        self.plot_file  = self.work_dir + "/stats.csv"
        # write once so that we have a valid stats file
        self.write_statistics()

    def event_database_cycle(self, pid, num_prog, num_unique):
        self.data["cycles"] += 1
        self.data["now_program_id"] = pid
        self.data["programs"] = num_prog
        self.data["unique_programs"] = num_unique

    def event_program_new(self, program): # TODO:
        self.update_yield(self.data["now_trying"])
        self.data["findings"]['regular'] += 1

        self.data["paths_total"] += 1
        self.data["paths_pending"] += 1

        if program.is_favorite():
            self.data["favs_total"] += 1
            self.data["favs_pending"] += 1

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

    def event_node_remove_fav_bit(self, program):
        # called when queue manager removed a fav bit from an existing program.
        # check if that was the last fav and maybe update #fav_pending count
        if not program.is_favorite():
            self.data["favs_total"] -= 1
            if program.get_state() != "final":
                self.data["favs_pending"] -= 1

    def event_slave_poll(self):
        # poll slave stats out of band - otherwise #execs are stalled by slow fuzz stages
        cur_execs = 0
        cur_funky = 0
        cur_reload = 0
        try:
            for slave_id in range(0, self.num_slaves):
                cur_execs  += self.read_slave_stats(slave_id).get("total_execs", 0)
                cur_funky  += self.read_slave_stats(slave_id).get("num_funky", 0)
                cur_reload += self.read_slave_stats(slave_id).get("num_reload", 0)
            self.data["total_execs"] = cur_execs
            self.data["num_funky"]   = cur_funky
            self.data["num_reload"] = cur_reload
        except:
            pass

    def event_program_initial(self, program):
        if program.is_initial() == True:
            program.unset_initial()
            self.data["paths_pending"] -= 1
            if program.is_favorite():
                self.data["favs_pending"] -= 1
        # self.maybe_write_stats()

    def maybe_write_stats(self):
        cur_time = time.time()

        if cur_time - self.write_last > self.write_thres:
            self.write_last = cur_time
            self.write_statistics()

        if cur_time - self.plot_last > self.plot_thres:
            self.plot_last = cur_time
            self.write_plot()

    def write_statistics(self):
        cur_time = time.time()
        self.data["run_time"] = cur_time - self.data["start_time"]
        self.data["execs/sec"] = self.data["total_execs"] / self.data["run_time"]
        atomic_write(self.stats_file, msgpack.packb(self.data, use_bin_type=True))

    def write_plot(self):
        cur_time = time.time()
        self.data["run_time"] = cur_time - self.data["start_time"]
        self.data["execs/sec"] = self.data["total_execs"] / self.data["run_time"]
        self.execs_last = self.data["total_execs"]
        self.execs_time = cur_time
        with open(self.plot_file, 'a') as fd:
            fd.write("%06d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d\n" % (
                self.data['run_time'],                 # elapsed time
                self.data["execs/sec"],                     # execs/sec
                self.data["paths_total"],      # paths total
                self.data["paths_pending"],    # paths pending
                self.data["favs_total"],       # favs total
                self.data["unique_findings"]["crash"],# unique crashes
                self.data["unique_findings"]["kasan"],# unique kasan
                self.data["unique_findings"]["timeout"], # unique timeout
                self.data["max_level"],        # max level
                self.data["cycles"],           # cycles
                self.data["favs_pending"],     # favs pending
                self.data["total_execs"],      # current total execs
                self.data["bytes_in_bitmap"],  # unique edges % p(col)
                ))

    def event_method(self, method, pid):
        self.data["now_trying"] = method

        self.data["now_program_id"] = pid
        self.maybe_write_stats()

    def event_exec(self):
        self.data["total_execs"] += 1
        self.data["stage"][self.data["now_trying"]] += 1
        self.maybe_write_stats()

    def event_reload(self):
        self.data["num_reload"] += 1
        self.maybe_write_stats()

    def event_funky(self):
        self.data["num_funky"] += 1
        self.maybe_write_stats()

    def get_total_execs(self):
        return self.data["total_execs"]