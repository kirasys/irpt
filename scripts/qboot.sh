#!/bin/sh
DIR="$( cd "$( dirname "$0" )" && pwd -P )"
cd $DIR
cd ..
cd qemu-5.0.0
./x86_64-softmmu/qemu-system-x86_64 \
	-machine q35 -enable-kvm -m 4000 -smp 4\
	-hda $1 -vga vmware \
	-chardev socket,server,nowait,path=../out/interface_0,id=kafl_interface \
	-device kafl,chardev=kafl_interface,bitmap_size=65536,shm0=../out/program,shm1=/dev/shm/kafl_out_qemu_payload_0,bitmap=/dev/shm/kafl_out_bitmap_0,redqueen_workdir=../out/redqueen_workdir_0,reload_mode=False \
	$2
