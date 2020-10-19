#!/bin/sh

cd ./qemu-5.0.0
./x86_64-softmmu/qemu-system-x86_64 \
	-machine q35 -cpu host -enable-kvm -m 4096 -smp cores=4 \
	-hda windows10.qcow2 -vga vmware \
	-net nic \
	-net user,hostfwd=tcp::2222-:22 \
	-chardev socket,server,nowait,path=/home/kirasys/kAFL/out/interface_0,id=kafl_interface \
	-device kafl,chardev=kafl_interface,bitmap_size=65536,shm0=/home/kirasys/kAFL/out/program,shm1=/dev/shm/kafl_out_qemu_payload_0,bitmap=/dev/shm/kafl_out_bitmap_0,redqueen_workdir=/home/kirasys/kAFL/out/redqueen_workdir_0,reload_mode=False,ip0_a=0xfffff8031da20000,ip0_b=0xfffff8031da27000 \
	$1
