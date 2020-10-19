cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_info.py \
    -vm_dir snapshot_win/ \
    -vm_ram snapshot_win/wram.qcow2 \
    -agent targets/windows_x86_64/bin/info/info.exe \
    -mem 4096 \
    -v \
    --purge \
    -work_dir out/ \
