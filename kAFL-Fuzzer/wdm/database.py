import json
import copy
import random

from common import rand
from wdm.program import Program

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else 0xffffffff)

def get_new_coverage_counts(bitmap, new_bitmap):
    count = 0
    for i in range(len(bitmap)):
        a = new_bitmap[i]
        if (a | bitmap[i]) != bitmap[i]:
            count += 1
    return count

class Database:
    def __init__(self, path):
        self.programs = []
        self.unique_programs = []
        self.interface = {}

        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InputBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutputBufferLength"]))

            self.interface[iocode] = {"InputBufferRange": inbuffer_ranges, "OutputBufferRange": outbuffer_ranges}

    def getAll(self):
        return self.programs

    def __unique_selection(self, new_programs):
        if len(self.programs) <= 0:
            return
        
        for new_program in new_programs:
            new_bitmap = new_program.bitmap
            # remove a duplicated program.
            i = 0
            while i < len(self.unique_programs):
                old_bitmap = self.unique_programs[i].bitmap
                count = get_new_coverage_counts(new_bitmap, old_bitmap)
                if count == 0:
                    self.unique_programs[i].dump("delete")
                    del self.unique_programs[i]
                else:
                    i += 1
            self.unique_programs.append(new_program)

    def getRandom(self):
        if len(self.programs) == 0: # generation
            program = Program(self.interface)
            program.generate()
            self.programs.append(program)
            return self.programs[0]

        if len(self.unique_programs) == 0 or rand.oneOf(10):        
            program = random.choice(self.programs)
        else:
            program = random.choice(self.unique_programs)
        return copy.deepcopy(program)
    
    def add(self, programs):
        self.programs += copy.deepcopy(programs)
        self.__unique_selection(programs)

        for p in self.unique_programs:
            p.dump("Unique program")
        print()
        print()
    
    def save(self):
        for p in self.unique_programs:
            p.save_to_file("unique")
        for p in self.programs:
            p.save_to_file("regular")
    