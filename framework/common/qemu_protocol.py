# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

ACQUIRE = b'R'
RELEASE = b'D'

RELOAD = b'L'
FINALIZE = b'F'

ENABLE_RQI_MODE = b'A'
DISABLE_RQI_MODE = b'B'

CRASH = b'C'
KASAN = b'K'
INFO = b'I'
TIMEOUT = b't'

PRINTF = b'X'

PT_TRASHED = b'Z'
PT_TRASHED_CRASH = b'M'
PT_TRASHED_KASAN = b'N'

ABORT = b'H'

# new
LOCK = b'l'
COVERAGE_ON = b'o'
COVERAGE_OFF = b'x'

CMDS = {
    ACQUIRE: "ACQUIRE",
    RELEASE: "RELEASE",
    RELOAD: "RELOAD",
    FINALIZE: "FINALIZE",

    ENABLE_RQI_MODE: "ENABLE_RQI_MODE",
    DISABLE_RQI_MODE: "DISABLE_RQI_MODE",

    CRASH: "CRASH",
    KASAN: "KASAN",
    INFO: "INFO",

    PRINTF: "PRINTF",

    PT_TRASHED: "PT_TRASHED",
    PT_TRASHED_CRASH: "PT_TRASHED_CRASH",
    PT_TRASHED_KASAN: "PT_TRASHED_KASAN",

    ABORT: "ABORT",
}

# Agent commands
EXECUTE_IRP = 0
DRIVER_REVERT = 1
DRIVER_RELOAD = 2
SCAN_PAGE_FAULT = 3
ANTI_IOCTL_FILTER = 4