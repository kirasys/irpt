#!/bin/sh

cd ./qemu-5.0.0
./x86_64-softmmu/qemu-system-x86_64 \
	-machine q35 -cpu host -enable-kvm -m 4096 -smp cores=4 \
	-hda windows10.qcow2 -vga vmware \
	-net nic \
	-net user,hostfwd=tcp::2222-:22
