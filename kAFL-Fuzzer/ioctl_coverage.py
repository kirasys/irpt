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

IRPT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
IRPT_CONFIG = IRPT_ROOT + "irpt.ini"

IOCTL_CODE_LIST = [0x222003, 0x222013, 0x222023]

def main():
    cfg = FuzzerConfiguration(IRPT_CONFIG)
    q = qemu(0, cfg, debug_mode=0)

    if not q.start():
        return

    exec_res = q.send_irp(IRP(IOCTL_CODE_LIST[0], 0, 0))
    for iocode in IOCTL_CODE_LIST[1:]:
        q.reload_driver()
        exec_res2 = q.send_irp(IRP(iocode, 0, 0))
        if exec_res.copy_to_array() != exec_res2.copy_to_array():
            print("IoControlCode(%x) == IoControlCode(%x)" % (IOCTL_CODE_LIST[0], iocode))
        else:
            print("IoControlCode(%x) != IoControlCode(%x)" % (IOCTL_CODE_LIST[0], iocode))
    
    q.shutdown()
if __name__ == "__main__":
    main()
