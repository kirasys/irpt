#!/bin/bash

sed -i '/qemu-5.0.0/c\qemu_kafl_location = '"$HOME"'/kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64' ~/kAFL/kAFL-Fuzzer/kafl.ini

mkdir ~/kAFL/snapshot_win
cd ~/kAFL/snapshot_win/

~/kAFL/qemu-5.0.0/qemu-img create -b ~/kAFL/qemu-5.0.0/windows10.qcow2 \
	-f qcow2 overlay_0.qcow2
~/kAFL/qemu-5.0.0/qemu-img create -f qcow2 wram.qcow2 4096

cd ~/kAFL
mkdir out/
~/kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 \
	-hdb ~/kAFL/snapshot_win/wram.qcow2 \
	-hda ~/kAFL/snapshot_win/overlay_0.qcow2 \
	-machine q35 -cpu host -smp cores=4 -serial mon:stdio \
	-net nic \
	-net user,hostfwd=tcp::2222-:22 \
	-enable-kvm -m 4096 \
