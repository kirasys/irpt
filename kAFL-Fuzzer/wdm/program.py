import copy
import random
import msgpack
import time

from common import rand
from common.config import FuzzerConfiguration
from common.util import array2int, int2array, p32, atomic_write

from wdm.irp import IRP
from wdm.interface import interface_manager
from debug.log import log

MAX_IRP_COUNT = 1000
MAX_PAYLOAD_LEN = 0x1000
MAX_DELTA = 35

class Program:
    NextID = 1

    def __init__(self, program_struct, irps=[], bitmap = None, exec_count = 0, complexity = 0, write = True):
        self.program_struct = program_struct
        self.irps = irps
        self.bitmap = bitmap

        self.set_id(Program.NextID, write=False)
        self.set_payload(self.serialize(), write=write)

        self.exec_count = exec_count
        self.complexity = complexity

    @staticmethod
    def get_metadata(id):
        return msgpack.unpackb(read_binary_file(Program.__get_metadata_filename(id)), raw=False, strict_map_key=False)

    @staticmethod
    def get_payload(exitreason, id):
        return read_binary_file(Program.__get_payload_filename(exitreason, id))

    def __get_bitmap_filename(self):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/bitmaps/payload_%05d.lz4" % (self.get_id())
        return workdir + filename

    @staticmethod
    def __get_payload_filename(exit_reason, id):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (exit_reason, id)
        return workdir + filename

    @staticmethod
    def __get_metadata_filename(id):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        return workdir + "/metadata/node_%05d" % id

    def update_file(self, write=True):
        if write:
            self.write_metadata()
            self.dirty = False
        else:
            self.dirty = True

    def write_bitmap(self, bitmap):
        atomic_write(self.__get_bitmap_filename(), lz4.frame.compress(bitmap))

    def write_metadata(self):

        return atomic_write(self.__get_metadata_filename(self.get_id()), msgpack.packb(self.program_struct, use_bin_type=True))

    def load_metadata(self):
        Program.get_metadata(self.id)

    def dump(self, label="PROGRAM"):
        # print("-------------%s--------------" % label)
        log(label)
        log(f"Exec count: {self.exec_count}", label="PROGRAM")
        log(f"Complexity: {self.complexity}", label="PROGRAM")
        log(f"ProgramID: {self.get_id()}", label="PROGRAM")

        for irp in self.irps:
            log("IoControlCode: %x InBuffer: %s" % (irp.IoControlCode, bytes(irp.InBuffer[:0xff])), label='PROGRAM')

    def map_density(self):
        return 100 * len(self.program_struct["new_bytes"]) / (64 * 1024)

    def serialize(self):
        data = b''
        for irp in self.irps:
            data += p32(irp.IoControlCode)
            data += p32(irp.InBufferLength)
            data += p32(irp.OutBufferLength)
            data += bytes(irp.InBuffer)
        return data

    def update_metadata(self, write=True):
        self.program_struct["info"]["time"] = time.time()
        self.program_struct["map_density"] = self.map_density()
        self.update_file(write=True)

    def set_payload(self, payload, write=True):
        self.set_payload_len(len(payload), write=False)
        atomic_write(Program.__get_payload_filename(self.get_exit_reason(), self.get_id()), payload)

    def set_payload_len(self, val, write=True):
        self.program_struct["payload_len"] = val
        self.update_file(write)

    def get_id(self):
        return self.program_struct["id"]

    def set_id(self, val, write=True):
        self.program_struct["id"] = val
        self.update_file(write)

    def get_new_bytes(self):
        return self.program_struct["new_bytes"]

    def set_new_bytes(self, val, write=True):
        self.program_struct["new_bytes"] = val
        self.update_file(write)

    def get_new_bits(self):
        return self.program_struct["new_bits"]

    def clear_fav_bits(self, write=True):
        self.program_struct["fav_bits"] = {}
        self.update_file(write)

    def get_fav_bits(self):
        return self.program_struct["fav_bits"]

    def add_fav_bit(self, index, write=True):
        self.program_struct["fav_bits"][index] = 0
        self.update_file(write)

    def remove_fav_bit(self, index, write=True):
        assert index in self.program_struct["fav_bits"]
        self.program_struct["fav_bits"].pop(index)
        self.update_file(write)

    def set_new_bits(self, val, write=True):
        self.program_struct["new_bits"] = val
        self.update_file(write)

    def get_level(self):
        return self.program_struct["level"]

    def set_level(self, val, write=True):
        self.program_struct["level"] = val
        self.update_file(write)

    def is_favorite(self):
        return len(self.program_struct["fav_bits"]) > 0

    def get_parent_id(self):
        return self.program_struct["info"]["parent"]

    def get_state(self):
        return self.program_struct["state"]["name"]

    def set_state(self, val, write=True):
        self.program_struct["state"]["name"] = val
        self.update_file(write)

    def get_exit_reason(self):
        return self.program_struct["info"]["exit_reason"]

    def set_exit_reason(self, val, write=True):
        self.program_struct["info"]["exit_reason"] = val
        self.update_file(write)

    def is_initial(self):
        return self.program_struct['state']['initial']

    def set_initial(self):
        self.program_struct['state']['initial'] = True

    def unset_initial(self):
        self.program_struct['state']['initial'] = False

    def save_to_file(self, exit_reason='regular'):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (exit_reason, Program.NextID)
        atomic_write(workdir + filename, self.serialize())
        # Program.NextID += 1

    def clone(self, **kwargs):
        return Program(exec_count=self.exec_count, complexity=self.complexity, **kwargs)

    def clone_with_irps(self, irps):
        program_struct = { # TODO self.program_struct
            'info':{
                'exit_reason': self.program_struct["info"]["exit_reason"], 
                'parent': self.get_id(), 
            },
            'level':self.program_struct['level'],
            'state':{'name':'initial', 'initial':False},
            'new_bytes':self.program_struct['new_bytes'],
            'new_bits':self.program_struct['new_bits'], 
            'fav_bytes':self.program_struct['fav_bytes'],
            'fav_bits':self.program_struct['fav_bits'],
            'fav_factor': self.program_struct['fav_factor']
        }            
        return self.clone(program_struct=program_struct, irps=copy.deepcopy(irps), bitmap=self.bitmap)
        
    def clone_with_bitmap(self, bitmap):
        program_struct = { # TODO self.program_struct
            'info':{
                'exit_reason': self.program_struct["info"]["exit_reason"], 
                'parent': self.get_parent_id(), 
            },
            'level':self.program_struct['level'],
            'state':{'name':'initial', 'initial':False},
            'new_bytes':self.program_struct['new_bytes'],
            'new_bits':self.program_struct['new_bits'], 
            'fav_bytes':self.program_struct['fav_bytes'],
            'fav_bits':self.program_struct['fav_bits'],
            'fav_factor': self.program_struct['fav_factor']
        }
        return self.clone(program_struct=program_struct, irps=self.irps, bitmap=bitmap)

    def __satisfiable(self, irp, length):
        inbuffer_ranges = interface_manager[irp.IoControlCode]["InBufferRange"]
        for rg in inbuffer_ranges:
            if length not in rg:
                return False
        return True

    def __generateIRP(self, iocode):
        inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
        outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

        inlength = 0
        outlength = 0xffffffff
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = min(outlength, rg.start)

        inlength = inlength if inlength <= MAX_PAYLOAD_LEN else MAX_PAYLOAD_LEN
        return IRP(iocode, inlength, outlength)

    def generate(self):
        for iocode in interface_manager.get_all_code():
            self.irps.append(self.__generateIRP(iocode))
    
    def mutate(self, corpus_programs):
        ok = False

        while len(self.irps) != 0 and not ok:
            if rand.oneOf(5):
                ok = self.__squashAny()
                method = "squashAny" if ok else None
            elif rand.nOutOf(1, 300):
                ok = self.__splice(corpus_programs)
                method = "AFLsplice" if ok else None
            elif rand.nOutOf(1, 200):
                ok = self.__insertIRP(corpus_programs)
                method = "insertIRP" if ok else None
            elif rand.nOutOf(1, 500):
                ok = self.__removeIRP()
                method = "removeIRP" if ok else None
            elif rand.nOutOf(1, 200):
                ok = self.__swapIRP()
                method = "swapIRP" if ok else None
            
            if rand.nOutOf(9, 11):
                ok = self.__mutateArg()
                method = "mutateArg" if ok else None
        
        self.set_state(method)
        return method

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
        idx = rand.Index(len(self.irps))
        self.irps = self.irps[:idx] + copy.deepcopy(p0.irps[:MAX_IRP_COUNT - idx])
        return True

    def __insertIRP(self, corpus_programs):
        """
        This function inserts a IRP at a randomly chosen point.
        A IRP which is inserted can be both new and old one.
        """
        if len(self.irps) >= MAX_IRP_COUNT:
            return False
        
        if rand.oneOf(2):   # generate a new irp.
            irp = self.__generateIRP(random.choice(list(interface_manager.get_all_code())))
        else:               # fetch a irp from other programs
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

                if not ok or self.__satisfiable(irp, len(irp.InBuffer)):
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
    