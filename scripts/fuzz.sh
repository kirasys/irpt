#!/bin/sh
cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_fuzz.py \
	-vm_ram snapshot_win/wram.qcow2 \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/fuzzer/medcored_test.exe \
	-mem 4096 \
	-seed_dir in/ \
	-work_dir out/ \
	-d \
	-v \
	--purge \
	-wdm toy_interface.json

