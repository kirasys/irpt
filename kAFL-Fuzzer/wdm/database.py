import json
import random
import numpy as np

from common import rand
from wdm.program import Program

def get_new_coverage_counts(bitmap, new_bitmap):
    count = 0
    for i in range(len(bitmap)):
        a = new_bitmap[i]
        if (a | bitmap[i]) != bitmap[i]:
            count += 1
    return count

COMPLEX_DOWN_THRESHOLD = 100

class Database:
    def __init__(self):
        self.programs = []
        self.unique_programs = []
        self.interface = {}

        self.probability_map = []

    def dump(self):
        for i, p in enumerate(self.unique_programs):
            p.dump("Unique program (%.2f%%)" % (self.probability_map[i]*100))
        print('\n')

    def getAll(self):
        return self.programs

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
        
        # Calculate the probabbility map.
        total_score = 0
        self.probability_map = []
        for uniq_program in self.unique_programs:
            score  = uniq_program.complexity
            score += len(set(uniq_program.coverage_map))
            score -= uniq_program.exec_count // COMPLEX_DOWN_THRESHOLD

            total_score += score
            self.probability_map.append(score)
        
        for i, uniq_program in enumerate(self.unique_programs):
            self.probability_map[i] /= total_score

    def get_next(self):
        if len(self.programs) == 0: # generation
            program = Program()
            program.generate()
            self.programs.append(program)
            return self.programs[0]

        if len(self.unique_programs) == 0 or rand.oneOf(10):        
            program = random.choice(self.programs)
        else:
            program = np.random.choice(self.unique_programs, p=self.probability_map)
        return program
    
    def add(self, programs):
        self.programs += programs
        self.__unique_selection(programs)

        self.dump()
    
    def save(self):
        for p in self.unique_programs:
            p.save_to_file("unique")
        for p in self.programs:
            p.save_to_file("regular")
    