#!/usr/bin/env python3
#
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import time
import random
import numpy as np

from common import rand
from debug.log import log
from wdm.program import Program

def get_new_coverage_counts(bitmap, new_bitmap):
    count = 0
    for i in range(len(bitmap)):
        a = new_bitmap[i]
        if (a | bitmap[i]) != bitmap[i]:
            count += 1
    return count

REMOVE_THRESHOLD = 1000

class Database:
    def __init__(self, statistics):
        self.statistics = statistics

        self.programs = []
        self.unique_programs = []
        self.interface = {}
        self.id_to_program = {}

        self.probability_map = []

        # default program generation
        program = Program()
        program.generate()

        self.programs.append(program)
        self.id_to_program[program.get_id()] = program

    def dump(self):
        for i, p in enumerate(self.unique_programs):
            p.dump(self.probability_map[i]*100)

    def get_programs(self):
        return self.programs
    
    def get_unique_programs(self):
        return self.unique_programs
    
    def get_last_program(self):
        return self.id_to_program[sorted(self.id_to_program)[-1]]

    def update_probability_map(self):
        # Calculate the probabbility map.
        total_score = 0
        self.probability_map = []
        for uniq_program in self.unique_programs:
            score  = REMOVE_THRESHOLD
            score += uniq_program.get_level() * 20
            score += len(set(uniq_program.coverage_map)) * 2
            score -= uniq_program.get_exec_count() * 20
            score  = max(score, 1)

            total_score += score
            self.probability_map.append(score)
        
        for i, uniq_program in enumerate(self.unique_programs):
            self.probability_map[i] /= total_score

    def __unique_selection(self, new_programs):
        if len(self.programs) <= 0:
            return
        
        for new_program in new_programs:
            new_coverage_set = set(new_program.coverage_map)

            # Remove a duplicated unique program.
            i = 0
            while i < len(self.unique_programs):
                old_coverage_set = set(self.unique_programs[i].coverage_map)
                
                count = 0
                for address in new_coverage_set:
                    if address in old_coverage_set:
                        count += 1

                if len(old_coverage_set) == count:
                    del self.unique_programs[i]
                    continue
                i += 1
            self.unique_programs.append(new_program)

        self.update_probability_map()

    def get_next(self):
        if len(self.unique_programs) == 0 or rand.oneOf(10):        
            program = random.choice(self.programs)
        else:
            program = np.random.choice(self.unique_programs, p=self.probability_map)
        
        program.increment_exec_count()
        self.statistics.event_database_cycle(program)
        return program
    
    def add(self, programs):
        for program in programs:
            program.set_parent_id(program.get_id())
            program.set_id() # get a new id
            program.set_dirty(True)
            program.set_exec_count(0)

            ppid = program.get_parent_id() # increment a level
            program.set_level(self.id_to_program[ppid].get_level() + 1 if ppid != 1 else 0)
            
            self.programs.append(program)
            self.id_to_program[program.get_id()] = program
            self.statistics.event_program_new(program)

        self.__unique_selection(programs)
    
    def save(self):
        for p in self.unique_programs:
            p.save_to_file("unique")
        for p in self.programs:
            p.save_to_file("regular")
    