# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Reimplementation of AFL-style arithmentic mutations (deterministic stage).
"""

from fuzzer.technique.helper import *
from common import rand
from binascii import hexlify

MAX_ARITHMETIC_SIZE = 0x200

def mutate_seq_8_bit_arithmetic(self, index):
    self.cur_program.set_state('seq_8bits_arithmetic')
    data = self.cur_program.irps[index].InBuffer
    
    # limit arithmethic up to MAX_ARITHMETIC_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_ARITHMETIC_SIZE:
        start = rand.Intn(((end - 1) // MAX_ARITHMETIC_SIZE)) * MAX_ARITHMETIC_SIZE
        end = min(end, start + MAX_ARITHMETIC_SIZE)

    for i in range(start, end):
        orig = data[i]

        for j in range(1, AFL_ARITH_MAX + 1):

            r1 = (orig + j) & 0xff
            r2 = (orig - j) & 0xff

            data[i] = r1
            if is_not_bitflip(orig^r1):
                if self.execute_irp(index):
                    return True

            data[i] = r2
            if is_not_bitflip(orig^r2):
                if self.execute_irp(index):
                    return True
        data[i] = orig

def mutate_seq_16_bit_arithmetic(self, index):
    self.cur_program.set_state('seq_16bits_arithmetic')
    data = self.cur_program.irps[index].InBuffer

    # limit arithmethic up to MAX_ARITHMETIC_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_ARITHMETIC_SIZE:
        start = rand.Intn(((end - 1) // MAX_ARITHMETIC_SIZE)) * MAX_ARITHMETIC_SIZE
        end = min(end, start + MAX_ARITHMETIC_SIZE)

    for i in range(start, end - 1):
        orig = data[i:i+2]
        num1 = (orig[0] << 8) | orig[1]
        num2 = (orig[1] << 8) | orig[0]

        for j in range(1, AFL_ARITH_MAX + 1):

            r1 = (num1 + j) & 0xffff
            r2 = (num1 - j) & 0xffff
            r3 = (num2 + j) & 0xffff
            r4 = (num2 - j) & 0xffff

            if is_not_bitflip(num1^r1) and num1^r1 > 0xff:
                data[i:i+2] = [r1 & 0xff, r1 >> 8]
                if self.execute_irp(index):
                    return True

            if is_not_bitflip(num1^r2) and num1^r2 > 0xff:
                data[i:i+2] = [r2 & 0xff, r2 >> 8]
                if self.execute_irp(index):
                    return True

            if is_not_bitflip(num2^r3) and swap_16(r1) != r3 and num2^r3 > 0xff:
                data[i:i+2] = [r3 & 0xff, r3 >> 8]
                if self.execute_irp(index):
                    return True

            if is_not_bitflip(num2^r4) and swap_16(r2) != r4 and num2^r4 > 0xff:
                data[i:i+2] = [r4 & 0xff, r4 >> 8]
                if self.execute_irp(index):
                    return True
            
        data[i:i+2] = orig


def mutate_seq_32_bit_arithmetic(self, index):
    self.cur_program.set_state('seq_32bits_arithmetic')
    data = self.cur_program.irps[index].InBuffer

    # limit arithmethic up to MAX_ARITHMETIC_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_ARITHMETIC_SIZE:
        start = rand.Intn(((end - 1) // MAX_ARITHMETIC_SIZE)) * MAX_ARITHMETIC_SIZE
        end = min(end, start + MAX_ARITHMETIC_SIZE)

    for i in range(start, end - 3):
        orig = data[i:i+4]
        num1 = (orig[3] << 24) | (orig[2] << 16) | (orig[1] << 8) | orig[0]
        num2 = (orig[0] << 24) | (orig[1] << 16) | (orig[2] << 8) | orig[3]

        for j in range(1, AFL_ARITH_MAX + 1):

            r1 = (num1 + j) & 0xffffffff
            r2 = (num1 - j) & 0xffffffff
            r3 = (num2 + j) & 0xffffffff
            r4 = (num2 - j) & 0xffffffff

            if is_not_bitflip(num1^r1) and (num1 & 0xffff) +j > 0xffff:
                data[i:i+4] = [r1 & 0xff, (r1 >> 8)&0xff, (r1 >> 16)&0xff, (r1 >> 24)&0xff]
                if self.execute_irp(index):
                    return True
            
            if is_not_bitflip(num1^r2) and num1 & 0xffff < j:
                data[i:i+4] = [r2 & 0xff, (r2 >> 8)&0xff, (r2 >> 16)&0xff, (r2 >> 24)&0xff]
                if self.execute_irp(index):
                    return True

            if is_not_bitflip(num2^r3) and (num2 & 0xffff) +j > 0xffff:
                data[i:i+4] = [r3 & 0xff, (r3 >> 8)&0xff, (r3 >> 16)&0xff, (r3 >> 24)&0xff]
                if self.execute_irp(index):
                    return True

            if is_not_bitflip(num2^r4) and num2 & 0xffff < j:
                data[i:i+4] = [r4 & 0xff, (r4 >> 8)&0xff, (r4 >> 16)&0xff, (r4 >> 24)&0xff]
                if self.execute_irp(index):
                    return True

        data[i:i+4] = orig
