import json
import random
import numpy as np
import time

from common import rand
from wdm.program import Program
from debug.log import log

def get_new_coverage_counts(bitmap, new_bitmap):
    count = 0
    for i in range(len(bitmap)):
        a = new_bitmap[i]
        if (a | bitmap[i]) != bitmap[i]:
            count += 1
    return count

COMPLEX_DOWN_THRESHOLD = 10000

class Database:
    def __init__(self, statistics):
        self.id_to_program = {}
        self.programs = []
        self.unique_programs = []
        self.interface = {}
        self.statistics = statistics

        self.probability_map = []

    def dump(self):
        for i, p in enumerate(self.unique_programs):
            p.dump("Unique program (%.2f%%)" % (self.probability_map[i]*100))
        print('\n')

    def getAll(self):
        return self.programs

    def __unique_selection(self, new_program):
        # if len(self.programs) <= 0:
        #     return

        # for new_program in new_programs:
        new_bitmap = new_program.bitmap

        # Remove a duplicated unique program.
        i = 0
        while i < len(self.unique_programs):
            old_bitmap = self.unique_programs[i].bitmap
            count = get_new_coverage_counts(new_bitmap, old_bitmap)
            if count == 0:  # duplicated coverage
                # self.unique_programs[i].dump("delete")
                del self.unique_programs[i]
                continue
            i += 1
        self.unique_programs.append(new_program)
        
        # Calculate the probabbility map.
        total_complexity = 0
        self.probability_map = []
        for uniq_program in self.unique_programs:
            probabbility = max(1, uniq_program.complexity - (uniq_program.exec_count // COMPLEX_DOWN_THRESHOLD))
            total_complexity += probabbility
            self.probability_map.append(probabbility)
        
        for i, uniq_program in enumerate(self.unique_programs):
            self.probability_map[i] /= total_complexity

    def get_next(self):
        if len(self.programs) == 0: # generation
            program_struct = {
                'info':{
                    'exit_reason': 'regular', 
                    'parent': 0, 
                },
                'level':0,
                'state':{'name':'initial', 'initial': True},
                'new_bytes':{},
                'new_bits':{}, 
                'fav_bytes':{},
                'fav_bits':{},
                'fav_factor': 0
            }
            program = Program(program_struct)
            program.generate()
            self.id_to_program[program.get_id()] = program
            self.programs.append(program)
            Program.NextID += 1

            self.statistics.event_program_new(program)
            self.statistics.event_database_cycle(program.program_struct["id"], len(self.programs), len(self.unique_programs))
            return self.programs[0]

        if len(self.unique_programs) == 0 or rand.oneOf(10):        
            program = random.choice(self.programs)
        else:
            program = np.random.choice(self.unique_programs, p=self.probability_map)

            self.statistics.event_database_cycle(program.program_struct["id"], len(self.programs), len(self.unique_programs))
        return program
    
    def add(self, programs):
        for program in programs:
            parent = program.get_parent_id()
            program.set_level(self.id_to_program[parent].get_level() + 1 if parent else 0, write=False)
            self.statistics.event_program_new(program)

            program.set_initial()
            self.id_to_program[program.get_id()] = program
            self.programs.append(program)
            self.update_program_results(program)
            Program.NextID += 1

            time.sleep(0.5)
            program.dump(f"[*] New program {program.get_id()}:")
            time.sleep(0.5)
            self.__unique_selection(program)

    def save(self):
        for p in self.unique_programs:
            p.save_to_file("unique")
        for p in self.programs:
            p.save_to_file("regular")

    def update_program_results(self, program):
        program.update_metadata()