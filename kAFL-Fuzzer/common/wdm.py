import copy
import json
import time
import random

from common import rand
from common.debug import log_process
from common.util import array2int, int2array

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else 0xffffffff)

class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer=''):
        self.IoControlCode = iocode
        self.InputBufferLength = inlength
        self.OutputBufferLength = outlength
        if inbuffer == '':
            self.InputBuffer = [ord('a')] * self.InputBufferLength
        else:
            self.InputBuffer = list(map(ord, inbuffer))

class IRPProgram:
    MAX_IRP_COUNT = 1000
    MAX_PAYLOAD_LEN = 0x1000
    maxDelta = 35

    def __init__(self, interface, irps=[]):
        self.irps = irps
        self.interface = interface

    def clone_with_interface(self, irps=[]):
        return IRPProgram(self.interface, copy.deepcopy(irps))

    def __satisfiable(self, irp, length):
        inbuffer_ranges = self.interface[irp.IoControlCode]["InputBufferRange"]
        for rg in inbuffer_ranges:
            if length not in rg:
                return False
        return True

    def __generateIRP(self, iocode):
        inbuffer_ranges = self.interface[iocode]["InputBufferRange"]
        outbuffer_ranges = self.interface[iocode]["OutputBufferRange"]

        inlength = 0
        outlength = 0xffffffff
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = min(outlength, rg.start)

        inlength = inlength if inlength <= IRPProgram.MAX_PAYLOAD_LEN else IRPProgram.MAX_PAYLOAD_LEN
        return IRP(iocode, inlength, outlength)

    def generate(self):
        for iocode in self.interface.keys():
            self.irps.append(self.__generateIRP(iocode))
    
    def mutate(self, corpus_programs):
        ok = False
        while len(self.irps) != 0 and not ok:
            if rand.oneOf(5):
                ok = self.__squashAny()
            elif rand.nOutOf(1, 100):
                ok = self.__splice(corpus_programs)
            elif rand.nOutOf(1, 400):
                ok = self.__insertIRP(corpus_programs)
            elif rand.nOutOf(1, 500):
                ok = self.__removeIRP()
            elif rand.nOutOf(1, 30):
                ok = self.__swapIRP()
            
            if rand.nOutOf(9, 11):
                ok = self.__mutateArg()

    def __squashAny(self):
        return False

    def __splice(self, corpus_programs):
        """
        This function selects a random other program p0 out of the corpus, and
        preserve self.irps up to a random index and concatenated with p0's irps from index
        """
        if len(corpus_programs) <= 1:
            return False
        
        p0 = random.choice(corpus_programs)
        idx = rand.Intn(len(self.irps))
        self.irps = self.irps[:idx] + copy.deepcopy(p0.irps[:IRPProgram.MAX_IRP_COUNT - idx])
        return True

    def __insertIRP(self, corpus_programs):
        """
        This function inserts a IRP at a randomly chosen point.
        A IRP which is inserted can be both new and old one.
        """
        if len(self.irps) >= IRPProgram.MAX_IRP_COUNT:
            return False
        
        if rand.oneOf(2):   # generate a new irp.
            irp = self.__generateIRP(random.choice(list(self.interface.keys())))
        else:               # fetch a irp from other programs
            program = random.choice(corpus_programs)
            irp = copy.deepcopy(random.choice(program.irps))

        # TODO: biasd random??
        self.irps.insert(rand.Intn(len(self.irps)), irp)
        return True

    def __swapIRP(self):
        """

        """
        idx1, idx2 = rand.Intn(len(self.irps)), rand.Intn(len(self.irps))
        if idx1 == idx2:
            return False

        self.irps[idx1], self.irps[idx2] = self.irps[idx2], self.irps[idx1]
        return True

    def __removeIRP(self):
        if len(self.irps) <= 1:
            return False

        idx = rand.Intn(len(self.irps))
        del self.irps[idx]
        return True

    def __mutateArg(self):
        idx = rand.Intn(len(self.irps))

        ok = False
        while not ok:
            ok = self.__mutateBuffer(self.irps[idx])

        return False
    
    def __mutateBuffer(self, irp):
        if len(irp.InputBuffer) == 0: # Case of InputBufferLenght == 0
            return True

        ok = False
        while not ok:
            if rand.nOutOf(7, 10):
                ok = self.__flipBit(irp.InputBuffer)
            elif rand.nOutOf(2, 10):
                ok = self.__addsubBytes(irp.InputBuffer)
            elif rand.nOutOf(1, 10):
                ok = self.__replaceBytes(irp.InputBuffer)
            else: # maybe change InputBufferLength
                if rand.nOutOf(1, 20):
                    ok = self.__insertBytes(irp.InputBuffer)
                else:
                    ok = self.__removeBytes(irp.InputBuffer)

                if not ok or self.__satisfiable(irp, len(irp.InputBuffer)):
                    continue

        return True
    
    def __flipBit(self, buffer):
        pos = rand.Intn(len(buffer))
        bit = rand.Intn(8)
        buffer[pos] ^= 1 << bit
        return True
    
    def __replaceBytes(self, buffer):
        width = 1 << rand.Intn(4)
        if len(buffer) < width:
            return False
        
        pos = rand.Intn(len(buffer) - width + 1)
        for i in range(width):
            buffer[pos + i] = rand.Intn(0xff)
        return True

    def __addsubBytes(self, buffer):
        width = 1 << rand.Intn(4)
        if len(buffer) < width:
            return False

        pos = rand.Intn(len(buffer) - width + 1)
        byts = buffer[pos:pos+width]
        delta = rand.Intn(2*IRPProgram.maxDelta + 1) - IRPProgram.maxDelta
        if delta == 0:
            delta = 1

        if rand.oneOf(10):
            v = array2int(byts[::-1])
            v += delta
            byts = int2array(v, width)[::-1]
        else:
            v = array2int(byts)
            v += delta
            byts = int2array(v, width)
        
        buffer[pos:pos+width] = byts
        return True
            
    def __insertBytes(self, buffer):
        n = rand.Intn(16) + 1
        if len(buffer) + n > IRPProgram.MAX_PAYLOAD_LEN:
            n = IRPProgram.MAX_PAYLOAD_LEN - len(buffer)
            if n == 0:
                return False
        
        arr = []
        for _ in range(n):
            arr.append(rand.Intn(0xff))
        pos = rand.Intn(len(buffer))
        buffer = buffer[:pos] + arr + buffer[pos:]
        return True
    
    def __removeBytes(self, buffer):
        n = rand.Intn(16) + 1
        pos = rand.Intn(len(buffer))
        buffer = buffer[:pos] + buffer[pos+n:]
        return True
    
    def __appendBunch(self, buffer):
        pass
    
    def dump(self):
        print("-------------Program--------------")
        for irp in self.irps:
            print("IoControlCode %x InputBuffer %s" % (irp.IoControlCode, bytes(irp.InputBuffer[:0x20])))
        print("----------------------------------")

class ProgramOptimizer:
    def __init__(self, q):
        self.q = q
        self.exec_results = []
    
    def clear(self):
        self.exec_results = []

    def add(self, program, exec_res, new_bytes, new_bits):
        self.exec_results.append([program, exec_res, new_bytes, new_bits])
    
    def __execute(self, program, reload=False):
        if reload:
            self.q.reload_driver()
        else:
            self.q.revert_driver()

        exec_res = None
        for irp in program.irps:
            exec_res = self.q.send_irp(irp)

        return exec_res.apply_lut()

    def optimizable(self):
        return len(self.exec_results) > 0

    def optimize(self):
        while len(self.exec_results):
            repro_program, old_res, new_bytes, new_bits = self.exec_results.pop()

            # quick validation for funky case.
            old_array = old_res.copy_to_array()
            new_res = self.__execute(repro_program, reload=True)
            new_array = new_res.copy_to_array()
            if new_array != old_array:
                log_process("[-] Reprodunction fail (funky case)")
                continue
                
            # program optimation
            if len(repro_program.irps) == 1:
                return repro_program

            valid_irps = []
            for i in range(len(repro_program.irps)):
                test_program = repro_program.clone_with_interface(repro_program.irps[:i] + repro_program.irps[i+1:])
                exec_res = self.__execute(test_program, reload=False)

                valid = False
                for index in new_bytes.keys():
                    if exec_res.cbuffer[index] != new_bytes[index]:
                        valid = True
                        break
                if not valid:
                    for index in new_bits.keys():
                        if exec_res.cbuffer[index] != new_bits[index]:
                            valid = True
                            break
                if valid:
                    valid_irps.append(repro_program.irps[i])

            if valid_irps:
                yield repro_program.clone_with_interface(valid_irps)


class ProgramDatabase:
    def __init__(self, path):
        self.programs = []
        self.interface = {}

        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InputBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutputBufferLength"]))

            self.interface[iocode] = {"InputBufferRange": inbuffer_ranges, "OutputBufferRange": outbuffer_ranges}

    def getInput(self):
        if len(self.programs) == 0: # generation
            program = IRPProgram(self.interface)
            program.generate()
            self.programs.append(program)
            return self.programs[0]

        # mutation
        program = random.choice(self.programs) # TODO: scoring programs
        mutated = copy.deepcopy(program)
        mutated.mutate(self.programs)
        return mutated
    
    def add(self, programs):
        self.programs += copy.deepcopy(programs)