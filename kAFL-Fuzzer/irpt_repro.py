#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launcher for Fuzzing with IRPT. Check fuzzer/core.py for more.
"""

import os
import sys

from wdm.irp import IRP
from common.config import FuzzerConfiguration
from common.qemu import qemu
from common.util import u32, read_binary_file

IRPT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
IRPT_CONFIG = IRPT_ROOT + "irpt.ini"


def main():
    cfg = FuzzerConfiguration(IRPT_CONFIG)
    q = qemu(0, cfg, debug_mode=0)

    if not q.start():
        return

    i = 0
    program_data = read_binary_file(IRPT_ROOT + "/../out/corpus/timeout/payload_00014")
    while i < len(program_data):
        iocode = u32(program_data[i:i+4])
        inlength = u32(program_data[i+4:i+8])
        outlength = u32(program_data[i+8:i+12])
        inputbuffer = str(program_data[i+12:i+12+inlength])
        exec_res = q.send_irp(IRP(iocode, inlength, outlength, inputbuffer))
        if exec_res.is_crash():
            print("Crashed!!")
            q.shutdown()
            return
        i = i+12+inlength

    q.send_irp(IRP(0, 0, 0))
    input("wait")
    q.shutdown()
if __name__ == "__main__":
    main()
