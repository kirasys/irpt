import copy
import random

from fuzzer.technique.helper import *

from common import rand
from binascii import hexlify

from wdm.interface import interface_manager
from fuzzer.technique.helper import MAX_RAND_VALUES_SIZE

def mutate_seq_8_bit_rand8bit(self, index):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end):
        orig = data[i]

        for _ in range(32):
            value = in_range_8(rand.Intn(0xff))
            if (is_not_bitflip(orig ^ value) and
                is_not_arithmetic(orig, value, 1) and
                is_not_interesting(orig, value, 1, 1)):
                    data[i] = value
                    if self.execute_irp(index):
                        return True

        data[i] = orig

def mutate_seq_16_bit_rand16bit(self, index):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end - 1):
        orig = data[i:i+2]
        oval = (orig[1] << 8) | orig[0]

        for _ in range(32):
            value = in_range_16((rand.Intn(0xff) << 8) | rand.Intn(0xff))
            if (is_not_bitflip(oval ^ value) and
                is_not_arithmetic(oval, value, 2) and
                is_not_interesting(oval, value, 2, 1)):
                    data[i:i+2] = [value & 0xff, value >> 8]
                    if self.execute_irp(index):
                        return True

        data[i:i+2] = orig

def mutate_seq_32_bit_rand32bit(self, index):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end - 3):
        orig = data[i:i+4]
        oval = (orig[3] << 24) | (orig[2] << 16) | (orig[1] << 8) | orig[0]

        for _ in range(32):
            value = in_range_32((rand.Intn(0xff) << 24) | (rand.Intn(0xff) << 16) | (rand.Intn(0xff) << 8) | rand.Intn(0xff))
            if (is_not_bitflip(oval ^ value) and
                is_not_arithmetic(oval, value, 4) and
                is_not_interesting(oval, value, 4, 1)):
                    data[i:i+4] = [value & 0xff, (value >> 8)&0xff, (value >> 16)&0xff, (value >> 24)&0xff]
                    if self.execute_irp(index):
                        return True

        data[i:i+4] = orig

def mutate_seq_32_bit_rand16bit(self, index):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end - 3):
        orig = data[i:i+4]
        oval = (orig[3] << 24) | (orig[2] << 16) | (orig[1] << 8) | orig[0]

        for _ in range(32):
            num1 = in_range_32((rand.Intn(0xff) << 8) | rand.Intn(0xff))
            num2 = swap_32(num1)

            if (is_not_bitflip(oval ^ num1) and
                is_not_arithmetic(oval, num1, 4) and
                is_not_interesting(oval, num1, 4, 1)):
                    data[i:i+4] = [num1 & 0xff, (num1 >> 8)&0xff, (num1 >> 16)&0xff, (num1 >> 24)&0xff]
                    if self.execute_irp(index):
                        return True
            
            if (is_not_bitflip(oval ^ num2) and
                is_not_arithmetic(oval, num2, 4) and
                is_not_interesting(oval, num2, 4, 1)):
                    data[i:i+4] = [num2 & 0xff, (num2 >> 8)&0xff, (num2 >> 16)&0xff, (num2 >> 24)&0xff]
                    if self.execute_irp(index):
                        return True

        data[i:i+4] = orig

def mutate_seq_64_bit_rand8bit(self, index):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end - 7):
        orig = data[i:i+8]

        for _ in range(32):
            num1 = in_range_64(rand.Intn(0xff))
            num2 = swap_64(num1)

            data[i:i+8] = [num1 & 0xff, (num1 >> 8)&0xff, (num1 >> 16)&0xff, (num1 >> 24)&0xff, \
                            (num1 >> 32)&0xff, (num1 >> 40)&0xff, (num1 >> 48)&0xff, (num1 >> 52)&0xff]
            if self.execute_irp(index):
                return True

            data[i:i+8] = [num2 & 0xff, (num2 >> 8)&0xff, (num2 >> 16)&0xff, (num2 >> 24)&0xff, \
                            (num2 >> 32)&0xff, (num2 >> 40)&0xff, (num2 >> 48)&0xff, (num2 >> 52)&0xff]
            if self.execute_irp(index):
                return True

        data[i:i+8] = orig

def mutate_buffer_length(self, index):
    irp = self.cur_program.irps[index]
    if irp.InBufferLength <= 1 or irp.OutBufferLength <= 1:
        return
    
    # When it is unable to change the length.
    if "InBufferLength" in interface_manager[irp.IoControlCode] or \
        "OutBufferLength" in interface_manager[irp.IoControlCode]:
        return

    orig = copy.deepcopy(irp)

    for _ in range(16):
        irp.OutBufferLength = rand.Index(orig.OutBufferLength)
        irp.InBufferLength = rand.Index(orig.InBufferLength)
        irp.InBuffer = orig.InBuffer[:irp.InBufferLength]

        if interface_manager.satisfiable(irp) and self.execute_irp(index):
            return True

    self.cur_program.irps[index] = orig

def bruteforce_irps(self):
    orilen = len(self.cur_program.irps)

    for _ in range(5):
        for _ in range(30):
            self.cur_program.irps += random.choice(self.database.getAll()).irps
            
        for i in range(len(self.cur_program.irps)):
            if self.execute_irp(i):
                return True

        self.cur_program.irps = self.cur_program.irps[:orilen]