#!/bin/sh

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 interface.json"
	exit 1
fi

cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_fuzz.py \
	-vm_ram snapshot_win/wram.qcow2 \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/agent/agent.exe \
	-mem 4096 \
	-seed_dir in/ \
	-work_dir out/ \
	-d \
	-v \
	--purge \
	-wdm $1

