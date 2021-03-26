# IRPT: The Art, Science, and Engineering of Windows driver fuzzing
IRPT is a fuzzer specialized in a windows driver. It measures the coverage of windows kernel using Intel PT technology and resolves global data problem and IOCTL dependency.

## Components of IRPT
**IRPT** consists of fuzzer, mutator, reproducer, optimizer, hypervisor and corpus database. Fuzzer brings a test case from `Corpus database` and sends mutated test case to `Hypervisor` via shared memory. The hypervisor measures its coverage and checks if new coverage or crash has been found. If the new coverage has been found, `Optimizer` verifies that a new coverage is measured again and sends to corpus database after minimization. If a crash is detected, `Reproducer` verifies that the crash occurs again and saves it as a file.

## Motivation
"kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels" noted that non-determinism due to kernel-space interrupts, kernel threads, statefulness, and similar mechanisms makes kernel fuzzing more difficult. The kernel region has a memory structure different from that of the user land, and the execution flow can be changed by various unexpected requests such as interrupts. So it is not easy to perform a fuzzing test focusing only on a specific target region.

In addition, instrumentation is required to receive feedback on coverage increase or decrease by executing the fuzzing routine. In the case of open source user land applications, it is possible to easily measure coverage by using a code compilation technique such as AFL, but since the Windows kernel is closed source, it is impossible to use the instrumentation technique to modify the inside of the code.

Accordingly, IRPT borrowed the idea of using intel-PT technology in the fuzzer from kAFL to measure the increase or decrease of coverage in the kernel. In addition, we modified the KVM-PT, QEMU-PT and hypercall communication technology developed by kAFL to implement communication between the VM loaded with the target driver and the fuzzer performing the mutation.

kAFL is a nice tool in that it enables hardware-assisted kernel fuzzing that is not dependent on the OS, but it is far from the ideal fuzzer that our pursues. The reason is that kAFL targets only a single IOCTL code. This means that the ordering dependency that exists between IOCTL routines cannot be considered.

Therefore, we tried to develop a fuzzer that solves the problems that kAFL cannot solve. Based on driver interface information that can be easily obtained using IREC.

## Getting started
Installation requires multiple components, some of which can depend on Internet connectivity and defaults 
of your distribution or version. It is recommended to install step by step. 

```bash
git clone irpt
cd ~/irpt
./install.sh deps     # check platform and install dependencies
./install.sh perms    # allow current user to control KVM (/dev/kvm)
./install.sh qemu     # git clone qemu-pt and build Qemu
./install.sh linux    # git clone kvm-pt and build Linux
```
It is safe to re-execute any of these commands after failure, for example if not all dependencies could have been downloaded.

```bash
./install.sh note
```
The final step does not automatically install the new Linux kernel but only gives some default instructions.
Install according to your preference/distribution defaults, or simply follow the suggested steps above.


```bash
$ sudo reboot
$ dmesg|grep VMX
[VMX-PT] Info:   CPU is supported!
```
After reboot, make sure the new kernel is booted and PT support is detected by KVM.
You must set the correct path to the Qemu binary in `kAFL-Fuzzer/irpt.ini`.


```bash
python irpt.py
```
Launch `irpt.py` to get a help message with the detailed list of parameters
<br><br>

### Setting QEMU
Before you launch `irpt.py`, you should be take a snapshot of QEMU with `loader.exe`.
It is a file to load a target driver and `agent.exe`.

```bash
~/irpt/targets/compile_loader.sh
```
If you prepare the binary in `targets/bin/loader.exe`, you can launch `vm.py` to take a snapshot of Qemu. 


```bash
python vm.py
```
Launch `vm.py` to get a help message with the detailed list of parameters:


> **Caution!** <br> Snapshot mode is not available to access internet. You can launch [vm.py](http://vm.py) with boot mode and download the binary inside the Qemu first.