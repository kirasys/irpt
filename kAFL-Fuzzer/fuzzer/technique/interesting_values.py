# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style 'interesting values' mutations (deterministic stage).
"""

from fuzzer.technique.helper import *
from binascii import hexlify

def mutate_seq_8_bit_interesting(index, self):
    data = self.cur_program.irps[index].InputBuffer

    for i in range(0, len(data)):
        orig = data[i]

        for j in range(len(interesting_8_Bit)):
            value = in_range_8(interesting_8_Bit[j])
            if (is_not_bitflip(orig ^ value) and
                is_not_arithmetic(orig, value, 1)):
                    data[i] = value
                    if self.execute_irp(index):
                        return True

        data[i] = orig


def mutate_seq_16_bit_interesting(index, self):
    data = self.cur_program.irps[index].InputBuffer

    for i in range(len(data) - 1):
        orig = data[i:i+2]
        oval = (orig[1] << 8) | orig[0]

        for j in range(len(interesting_16_Bit)):
            num1 = in_range_16(interesting_16_Bit[j])
            num2 = swap_16(num1)

            if (is_not_bitflip(oval ^ num1) and
                is_not_arithmetic(oval, num1, 2, arith_max=AFL_ARITH_MAX) and
                is_not_interesting(oval, num1, 2, 0)):
                    data[i:i+2] = [num1 & 0xff, num1 >> 8]
                    if self.execute_irp(index):
                        return True

            if (num1 != num2 and \
                is_not_bitflip(oval ^ num2) and \
                is_not_arithmetic(oval, num2, 2, arith_max=AFL_ARITH_MAX) and \
                is_not_interesting(oval, num2, 2, 1)):
                    data[i:i+2] = [num2 & 0xff, num2 >> 8]
                    if self.execute_irp(index):
                        return True

        data[i:i+2] = orig


def mutate_seq_32_bit_interesting(index, self):
    data = self.cur_program.irps[index].InputBuffer

    for i in range(len(data) - 3):
        orig = data[i:i+4]
        oval = (orig[3] << 24) | (orig[2] << 16) | (orig[1] << 8) | orig[0]

        for j in range(len(interesting_32_Bit)):

            num1 = in_range_32(interesting_32_Bit[j])
            num2 = swap_32(num1)

            if (is_not_bitflip(oval ^ num1) and \
                is_not_arithmetic(oval, num1, 4, arith_max=AFL_ARITH_MAX) and \
                is_not_interesting(oval, num1, 4, 0)):
                    data[i:i+4] = [num1 & 0xff, (num1 >> 8)&0xff, (num1 >> 16)&0xff, (num1 >> 24)&0xff]
                    if self.execute_irp(index):
                        return True

            if (num1 != num2 and is_not_bitflip(oval ^ num2) and
                is_not_arithmetic(oval, num2, 4, arith_max=AFL_ARITH_MAX) and
                is_not_interesting(oval, num2, 4, 1)):
                    data[i:i+4] = [num2 & 0xff, (num2 >> 8)&0xff, (num2 >> 16)&0xff, (num2 >> 24)&0xff]
                    if self.execute_irp(index):
                        return True

        data[i:i+4] = orig
