#!/bin/sh
cd ~/kAFL/
python3 kAFL-Fuzzer/crash_repro.py \
	-vm_ram snapshot_win/wram.qcow2 \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/agent/agent.exe \
	-mem 4096 \
	-seed_dir in/ \
	-work_dir repro_out/ \
	-d \
	-v \
	--purge

