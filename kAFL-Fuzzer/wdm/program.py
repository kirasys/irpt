import copy
import random

from common import rand
from common.config import FuzzerConfiguration
from common.util import array2int, int2array, p32, atomic_write

from wdm.irp import IRP

class Program:
    MAX_IRP_COUNT = 1000
    MAX_PAYLOAD_LEN = 0x1000
    maxDelta = 35

    NextID = 0
    def __init__(self, interface, irps=[], bitmap=None):
        self.irps = irps
        self.interface = interface
        self.bitmap = bitmap

    def dump(self, label="Program"):
        print("-------------%s--------------" % label)
        for irp in self.irps:
            print("IoControlCode %x InputBuffer %s" % (irp.IoControlCode, bytes(irp.InputBuffer[:0x20])))
        print("----------------------------------")

    def serialize(self):
        data = b''
        for irp in self.irps:
            data += p32(irp.IoControlCode)
            data += p32(irp.InputBufferLength)
            data += p32(irp.OutputBufferLength)
            data += bytes(irp.InputBuffer)
        return data

    def save_to_file(self, exit_reason='regular'):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (exit_reason, Program.NextID)
        atomic_write(workdir + filename, self.serialize())
        Program.NextID += 1

    def clone_with_irps(self, irps):
        return Program(self.interface, irps=copy.deepcopy(irps), bitmap=self.bitmap)
    
    def clone_with_bitmap(self, bitmap):
        return Program(self.interface, irps=self.irps, bitmap=bitmap)

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

        inlength = inlength if inlength <= Program.MAX_PAYLOAD_LEN else Program.MAX_PAYLOAD_LEN
        return IRP(iocode, inlength, outlength)

    def generate(self):
        for iocode in self.interface.keys():
            self.irps.append(self.__generateIRP(iocode))
    
    def mutate(self, corpus_programs):
        ok = False
        while len(self.irps) != 0 and not ok:
            if rand.oneOf(5):
                ok = self.__squashAny()
            elif rand.nOutOf(1, 300):
                ok = self.__splice(corpus_programs)
            elif rand.nOutOf(1, 200):
                ok = self.__insertIRP(corpus_programs)
            elif rand.nOutOf(1, 500):
                ok = self.__removeIRP()
            elif rand.nOutOf(1, 200):
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
        self.irps = self.irps[:idx] + copy.deepcopy(p0.irps[:Program.MAX_IRP_COUNT - idx])
        return True

    def __insertIRP(self, corpus_programs):
        """
        This function inserts a IRP at a randomly chosen point.
        A IRP which is inserted can be both new and old one.
        """
        if len(self.irps) >= Program.MAX_IRP_COUNT:
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
        delta = rand.Intn(2*Program.maxDelta + 1) - Program.maxDelta
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
        if len(buffer) + n > Program.MAX_PAYLOAD_LEN:
            n = Program.MAX_PAYLOAD_LEN - len(buffer)
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
    