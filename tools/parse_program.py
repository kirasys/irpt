#!/usr/bin/env python3
#
# Copyright (C) 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import sys
import struct

u32 = lambda x : struct.unpack('<I', x)[0]

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def main():
    i = 0
    program_data = read_binary_file(sys.argv[1])
    while i < len(program_data):
        iocode = u32(program_data[i:i+4])
        inlength = u32(program_data[i+4:i+8])
        outlength = u32(program_data[i+8:i+12])
        inbuffer = str(program_data[i+12:i+12+inlength])
        
        print('IoControlCode :', hex(iocode))
        print("InBufferLength :", hex(inlength))
        print("OutBufferLength :", hex(outlength))
        print("InBuffer : ", inbuffer)
        print()
        i = i+12+inlength
    
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s payload_file" % sys.argv[0])
        sys.exit(1)
    main()