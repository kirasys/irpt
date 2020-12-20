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

from debug.log import log

from wdm.irp import IRP
from common.config import FuzzerConfiguration
from common.qemu import qemu
from common.util import u32, read_binary_file

IRPT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
IRPT_CONFIG = IRPT_ROOT + "irpt.ini"

def main():
    cfg = FuzzerConfiguration(IRPT_CONFIG)
    payload = read_binary_file(cfg.argument_values['payload'])
    q = qemu(0, cfg, debug_mode=0)

    if not q.start():
        return

    i = 0
    while i < len(payload):
        iocode = u32(payload[i:i+4])
        inlength = u32(payload[i+4:i+8])
        outlength = u32(payload[i+8:i+12])
        inbuffer = str(payload[i+12:i+12+(inlength & 0xFFFFFF)])
        log("[+] IoControlCode(%x) InBufferLength(%d)" % (iocode, inlength))
        
        exec_res = q.send_irp(IRP(iocode, inlength, outlength, inbuffer))
        if exec_res.is_crash():
            if not exec_res.is_timeout():
                log("Crashed!!")
            else:
                log("Timeout!!")
            q.shutdown()
            return

        i = i + 12 + inlength
    q.shutdown()
    
if __name__ == "__main__":
    main()
