# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style bitflip mutations (deterministic stage).
"""

def walking_bits_execs(data, skip_null=False, effector_map=None):
    execs=0
    for i in range(len(data) * 8):
        if effector_map:
            if not effector_map[i // 8]:
                continue
        if data[i // 8] == 0x00 and skip_null:
            continue

        execs +=1

    return execs


def mutate_seq_walking_bits(index, self):
    data = self.cur_program.irps[index].InBuffer
    for i in range(len(data) * 8):
        data[i // 8] ^= (0x80 >> (i % 8))
        if self.execute_irp(index):
            return True
        data[i // 8] ^= (0x80 >> (i % 8))


def mutate_seq_two_walking_bits(index, self):
    data = self.cur_program.irps[index].InBuffer
    for i in range((len(data) * 8) - 1):
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        if self.execute_irp(index):
            return True
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))


def mutate_seq_four_walking_bits(index, self):
    data = self.cur_program.irps[index].InBuffer
    for i in range((len(data) * 8 - 3)):
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) // 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) // 8] ^= (0x80 >> ((i + 3) % 8))
        if self.execute_irp(index):
            return True
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) // 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) // 8] ^= (0x80 >> ((i + 3) % 8))


def mutate_seq_walking_byte(index, self):
    data = self.cur_program.irps[index].InBuffer
    for i in range(len(data)):
        data[i] ^= 0xFF
        if self.execute_irp(index):
            return True
        data[i] ^= 0xFF


def mutate_seq_two_walking_bytes(index, self):
    data = self.cur_program.irps[index].InBuffer

    if len(data) <= 1:
        return

    for i in range(0, len(data)-1):
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        if self.execute_irp(index):
            return True
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF


def mutate_seq_four_walking_bytes(index, self):
    data = self.cur_program.irps[index].InBuffer
    if len(data) <= 3:
        return

    for i in range(0, len(data)-3):
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
        if self.execute_irp(index):
            return True
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
