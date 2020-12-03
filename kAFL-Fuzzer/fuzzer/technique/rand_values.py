from fuzzer.technique.helper import *
from common import rand
from binascii import hexlify

MAX_RAND_VALUES_SIZE = 0x100

def mutate_seq_8_bit_rand8bit(index, self):
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
                is_not_arithmetic(orig, value, 1)):
                    data[i] = value
                    if self.execute_irp(index):
                        return True

        data[i] = orig

def mutate_seq_64_bit_rand8bit(index, self):
    data = self.cur_program.irps[index].InBuffer

    # limit interesting up to MAX_RAND_VALUES_SIZE.
    start, end = 0, self.cur_program.irps[index].InBufferLength
    if end > MAX_RAND_VALUES_SIZE:
        start = rand.Intn(((end - 1) // MAX_RAND_VALUES_SIZE)) * MAX_RAND_VALUES_SIZE
        end = min(end, start + MAX_RAND_VALUES_SIZE)

    for i in range(start, end - 7):
        orig = data[i:i+8]

        for _ in range(16):
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