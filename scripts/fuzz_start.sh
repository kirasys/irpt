#!/bin/bash

python3 kAFL-Fuzzer/kafl_fuzz.py -vm_ram snapshot_win/wram.qcow2 -vm_dir snapshot_win/ -agent targets/windows_x86_64/bin/fuzzer/medcored_test.exe -mem 4096 -seed_dir in/ -work_dir out/ -ip0 0xfffff804811c0000-0xfffff804812c5000 -d -v --purge -p 1
