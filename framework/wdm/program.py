#!/usr/bin/env python3
#
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import copy
import time
import random
import msgpack

from debug.log import log

from common import rand
from common.config import FuzzerConfiguration
from common.util import array2int, int2array, p32, u32, atomic_write, read_binary_file, MAX_RANGE_VALUE

from wdm.irp import IRP
from wdm.interface import interface_manager

MAX_IRP_COUNT = 100
MAX_BUFFER_LEN = 0x200
MAX_DELTA = 35

class Program:
    NextID = 0
    PayloadCount = 0
    
    def __init__(self, program_struct=None, irps=None, bitmap=None, coverage_map=None):
        if program_struct is None:
            program_struct = {
                'info':{
                    'exit_reason': 'regular', 
                    'parent': 0, 
                },
                'level':0,
                'exec_count':0,
                'state':'initial',
                'new_bytes':{},
                'new_bits':{}, 
                'fav_bytes':{},
                'fav_bits':{},
                'dirty': True,
                'initial': False
            }
        else:
            program_struct = copy.deepcopy(program_struct)
        self.program_struct = program_struct

        if irps is None:
            irps = []
        else:
            irps = copy.deepcopy(irps)
        self.irps = irps

        self.bitmap = bitmap
        self.coverage_map = coverage_map
        self.set_id()

    def dump(self, percent=0):
        log("id=%d, percent=%.2f%%, exec_count=%d, level=%d" 
            % (self.get_id(), percent, self.get_exec_count(), self.get_level()), label="PROGRAM")

        for irp in self.irps:
            log("IoControlCode=%x, InBuffer=%s" % (irp.IoControlCode, bytes(irp.InBuffer[:0x10])), label='PROGRAM')
        log('', label='')

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

    def save_to_file(self, label):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (label, Program.PayloadCount)
        atomic_write(workdir + filename, self.serialize())
        Program.PayloadCount += 1


    def clone_with_irps(self, irps):
        cloned = copy.deepcopy(self)
        cloned.irps = copy.deepcopy(irps)
        return cloned

    def __generateIRP(self, iocode):
        inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
        outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

        inlength = 0
        outlength = 0
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = max(outlength, rg.stop - 1)

        inlength = inlength if inlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        outlength = outlength if outlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        return IRP(iocode, inlength, outlength)

    def generate(self):
        for iocode in interface_manager.get_all_codes():
            self.irps.append(self.__generateIRP(iocode))
    
    def mutate(self, corpus_programs):
        if rand.oneOf(10):
            self.__splice(corpus_programs)
        elif rand.oneOf(10):
            self.__swapIRP()
        elif rand.oneOf(10):
            self.__insertIRP(corpus_programs)
        elif rand.oneOf(20):
            self.__removeIRP()

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

        irp = self.__generateIRP(random.choice(list(interface_manager.get_all_codes())))

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
        self.set_dirty()
        idx = rand.Index(len(self.irps))

        ok = False
        while not ok:
            ok = self.__mutateBuffer(self.irps[idx])
        return ok
    
    def __mutateBuffer(self, irp):
        if len(irp.InBuffer) == 0: # Case of InBufferLenght == 0
            return True

        ok = False
        while not ok:
            ok = self.__replaceBytes(irp.InBuffer)
        return True

    
    def __replaceBytes(self, buffer):
        width = 1 << rand.Index(4)
        if len(buffer) < width:
            width = len(buffer)
        
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
        if len(buffer) + n > MAX_BUFFER_LEN:
            n = MAX_BUFFER_LEN - len(buffer)
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
    
    @staticmethod
    def __get_metadata_filename(id):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        return workdir + "/metadata/node_%05d" % id

    def write_metadata(self):
        return atomic_write(self.__get_metadata_filename(self.get_id()), msgpack.packb(self.program_struct, use_bin_type=True))

    def update_file(self, write=True):
        if write:
            self.write_metadata()
            self.dirty = False
        else:
            self.dirty = True

    def get_parent_id(self):
        return self.program_struct["info"]["parent"]

    def set_parent_id(self, val):
        self.program_struct["info"]["parent"] = val

    def get_id(self):
        return self.program_struct["id"]

    def set_id(self):
        Program.NextID += 1
        self.program_struct["id"] = Program.NextID

    def get_new_bytes(self):
        return self.program_struct["new_bytes"]

    def set_new_bytes(self, val):
        self.program_struct["new_bytes"] = val
    
    def get_new_bits(self):
        return self.program_struct["new_bits"]

    def set_new_bits(self, val):
        self.program_struct["new_bits"] = val
    
    def clear_fav_bits(self):
        self.program_struct["fav_bits"] = {}

    def get_fav_bits(self):
        return self.program_struct["fav_bits"]

    def add_fav_bit(self, index):
        self.program_struct["fav_bits"][index] = 0

    def remove_fav_bit(self, index):
        assert index in self.program_struct["fav_bits"]
        self.program_struct["fav_bits"].pop(index)
        
    def is_favorite(self):
        return len(self.program_struct["fav_bits"]) > 0

    def get_exec_count(self):
        return self.program_struct["exec_count"]
    
    def set_exec_count(self, val):
        self.program_struct["exec_count"] = val

    def increment_exec_count(self):
        self.program_struct["exec_count"] += 1

    def get_level(self):
        return self.program_struct["level"]

    def set_level(self, val):
        self.program_struct["level"] = val

    def set_state(self, val):
        self.program_struct["state"] = val

    def get_state(self):
        return self.program_struct["state"]

    def map_density(self):
        return 100 * len(self.program_struct["new_bytes"]) / (64 * 1024)

    def is_initial(self):
        return self.program_struct["initial"]

    def set_initial(self):
        self.program_struct["initial"] = True

    def unset_initial(self):
        self.program_struct["initial"] = False

    def get_dirty(self):
        return self.program_struct["dirty"]

    def set_dirty(self, v=True):
        self.program_struct["dirty"] = v