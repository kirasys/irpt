# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Startup routines for IRPT Fuzzer.

Spawn a Master and one or more Slave processes, where Master implements the
global fuzzing queue and scheduler and Slaves implement mutation stages and
Qemu/KVM execution.

Prepare the IRPT workdir and copy any provided seeds to be picked up by the scheduler.
"""

import multiprocessing
import time
import pgrep
import sys

from common.debug import enable_logging
from common.self_check import post_self_check
from common.util import prepare_working_dir, print_fail, print_note, print_warning, copy_seed_files
from fuzzer.process.process import Process
from wdm.interface import interface_manager
def qemu_sweep():
    pids = pgrep.pgrep("qemu")

    if (len(pids) > 0):
        print_warning("Detected potential qemu zombies, please kill -9: " + repr(pids))


def graceful_exit(slaves):
    for s in slaves:
        s.terminate()

    print("Waiting for Slave instances to shutdown...")
    time.sleep(1)

    while len(slaves) > 0:
        for s in slaves:
            if s and s.exitcode is None:
                print("Still waiting on %s (pid=%d)..  [hit Ctrl-c to abort..]" % (s.name,s.pid))
                s.join(timeout=1)
            else:
                slaves.remove(s)


def start(config):

    if not post_self_check(config):
        return -1
    
    work_dir   = config.argument_values["work_dir"]
    seed_dir   = config.argument_values["seed_dir"]
    
    if config.argument_values['v'] or config.argument_values['debug']:
        enable_logging(work_dir)

    if not prepare_working_dir(config):
        print_fail("Refuse to operate on existing work directory. Use --purge to override.")
        return 1

    if seed_dir and not copy_seed_files(work_dir, seed_dir):
        print_fail("Error when importing seeds. Exit.")
        return 1

    # Copy a driver file to agent.
    

    # Load WDM Interface information.
    interface_manager.load(config.argument_values['interface'])

    # Start IRPT!
    proc = Process(config)
    try:
        proc.loop()
    except KeyboardInterrupt:
        print_note("Received Ctrl-C")
    finally:
        proc.database.save()
        proc.shutdown()

    time.sleep(0.2)
    qemu_sweep()
    sys.exit(0)
