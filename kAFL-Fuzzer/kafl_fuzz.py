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
import signal

import common.color
from common.self_check import self_check
from common.config import FuzzerConfiguration

IRPT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
IRPT_BANNER = IRPT_ROOT + "banner.txt"
IRPT_CONFIG = IRPT_ROOT + "irpt.ini"

def sigint_handler(sig, frame):
    sys.exit(0)

def main():
    if not self_check(IRPT_ROOT):
        return 1

    signal.signal(signal.SIGINT, sigint_handler)
    
    config = FuzzerConfiguration(IRPT_CONFIG)
    if config.argument_values['tui']:
        from debug.log import disable_log
        disable_log()

    import fuzzer.core
    return fuzzer.core.start(config)


if __name__ == "__main__":
    main()
