import copy
import random

from common import rand
from common.config import FuzzerConfiguration
from common.util import array2int, int2array, p32, u32, atomic_write, read_binary_file, MAX_RANGE_VALUE

from wdm.irp import IRP
from wdm.interface import interface_manager

MAX_IRP_COUNT = 1000
MAX_PAYLOAD_LEN = 0x200
MAX_DELTA = 35

class Program:
    NextID = 0
    
    def __init__(self, irps=None, bitmap=None, coverage_map=None,complexity=0, exec_count=0):
        if irps is None:
            irps = []
        self.irps = irps
        self.bitmap = bitmap
        self.coverage_map = coverage_map

        self.exec_count = exec_count
        self.complexity = complexity

    def dump(self, label="Program"):
        print("-------------%s--------------" % label)
        print("Exec count : %d " % self.exec_count)
        print("Complexity : %d " % self.complexity)
        for irp in self.irps:
            print("IoControlCode : 0x%x\n InBufferLength 0x%x" % (irp.IoControlCode, irp.InBufferLength))
            print(bytes(irp.InBuffer[:0x20]))
        #print(list(map(hex, self.coverage_map)))
        print("----------------------------------")

    def load(self, f):
        i = 0
        program_data = read_binary_file(f)
        while i < len(program_data):
            iocode = u32(program_data[i:i+4])
            inlength = u32(program_data[i+4:i+8])
            outlength = u32(program_data[i+8:i+12])
            inbuffer = str(program_data[i+12:i+12+inlength])
            self.irps.append(IRP(iocode, inlength, outlength, inbuffer))
            i = i + 12 + inlength

    def serialize(self):
        data = b''
        for irp in self.irps:
            data += p32(irp.IoControlCode)
            data += p32(irp.InBufferLength)
            data += p32(irp.OutBufferLength)
            data += bytes(irp.InBuffer)
        return data

    def save_to_file(self, exit_reason='regular'):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (exit_reason, Program.NextID)
        atomic_write(workdir + filename, self.serialize())
        Program.NextID += 1

    def clone(self, **kwargs):
        return Program(exec_count=self.exec_count, complexity=self.complexity, **kwargs)

    def clone_with_irps(self, irps):
        return self.clone(irps=copy.deepcopy(irps), bitmap=self.bitmap, coverage_map=self.coverage_map)

    def __generateIRP(self, iocode):
        inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
        outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

        inlength = 0
        outlength = MAX_RANGE_VALUE
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = min(outlength, rg.start)

        inlength = inlength if inlength != MAX_RANGE_VALUE-1 else MAX_PAYLOAD_LEN
        return IRP(iocode, inlength, outlength)

    def generate(self):
        for iocode in interface_manager.get_all_code():
            self.irps.append(self.__generateIRP(iocode))
    
    def mutate(self, corpus_programs):
        ok = False
        while len(self.irps) != 0 and not ok:
            if rand.nOutOf(1, 100):
                ok = self.__splice(corpus_programs)
            elif rand.nOutOf(1, 100):
                ok = self.__insertIRP(corpus_programs)
            elif rand.nOutOf(1, 200):
                ok = self.__swapIRP()
            
            if rand.nOutOf(9, 11):
                ok = self.__mutateArg()

    def __splice(self, corpus_programs):
        """
        This function selects a random other program p0 out of the corpus, and
        preserve self.irps up to a random index and concatenated with p0's irps from index
        """
        if len(corpus_programs) <= 1:
            return False
        
        p0 = random.choice(corpus_programs)
        self.irps += copy.deepcopy(p0.irps)
        return True

    def __insertIRP(self, corpus_programs):
        """
        This function inserts a IRP at a randomly chosen point.
        A IRP which is inserted can be both new and old one.
        """
        if len(self.irps) >= MAX_IRP_COUNT:
            return False
        # fetch a irp from other programs
        program = random.choice(corpus_programs)
        irp = copy.deepcopy(random.choice(program.irps))

        # TODO: biasd random??
        self.irps.insert(rand.Index(len(self.irps)), irp)
        return True

    def __swapIRP(self):
        """

        """
        idx1, idx2 = rand.Index(len(self.irps)), rand.Index(len(self.irps))
        if idx1 == idx2:
            return False

        self.irps[idx1], self.irps[idx2] = self.irps[idx2], self.irps[idx1]
        return True

    def __removeIRP(self):
        if len(self.irps) <= 1:
            return False

        idx = rand.Index(len(self.irps))
        del self.irps[idx]
        return True

    def __mutateArg(self):
        idx = rand.Index(len(self.irps))

        ok = False
        while not ok:
            ok = self.__mutateBuffer(self.irps[idx])

        return False
    
    def __mutateBuffer(self, irp):
        if len(irp.InBuffer) == 0: # Case of InBufferLenght == 0
            return True

        ok = False
        while not ok:
            if rand.nOutOf(7, 10):
                ok = self.__flipBit(irp.InBuffer)
            elif rand.nOutOf(2, 10):
                ok = self.__addsubBytes(irp.InBuffer)
            elif rand.nOutOf(1, 10):
                ok = self.__replaceBytes(irp.InBuffer)
            else: # maybe change InBufferLength
                if rand.nOutOf(1, 20):
                    ok = self.__insertBytes(irp.InBuffer)
                else:
                    ok = self.__removeBytes(irp.InBuffer)

                if not ok or interface_manager.satisfiable(irp):
                    continue

        return True
    
    def __flipBit(self, buffer):
        pos = rand.Index(len(buffer))
        bit = rand.Index(8)
        buffer[pos] ^= 1 << bit
        return True
    
    def __replaceBytes(self, buffer):
        width = 1 << rand.Index(4)
        if len(buffer) < width:
            return False
        
        pos = rand.Index(len(buffer) - width + 1)
        for i in range(width):
            buffer[pos + i] = rand.Intn(0xff)
        return True

    def __addsubBytes(self, buffer):
        width = 1 << rand.Index(4)
        if len(buffer) < width:
            return False

        pos = rand.Index(len(buffer) - width + 1)
        byts = buffer[pos:pos+width]
        delta = rand.Index(2*MAX_DELTA + 1) - MAX_DELTA
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
        n = rand.Index(16) + 1
        if len(buffer) + n > MAX_PAYLOAD_LEN:
            n = MAX_PAYLOAD_LEN - len(buffer)
            if n == 0:
                return False
        
        arr = []
        for _ in range(n):
            arr.append(rand.Intn(0xff))
        pos = rand.Index(len(buffer))
        buffer = buffer[:pos] + arr + buffer[pos:]
        return True
    
    def __removeBytes(self, buffer):
        n = rand.Index(16) + 1
        pos = rand.Index(len(buffer))
        buffer = buffer[:pos] + buffer[pos+n:]
        return True
    
    def __appendBunch(self, buffer):
        pass
    