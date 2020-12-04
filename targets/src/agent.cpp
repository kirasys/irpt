/*

Copyright (C) 2017 Robert Gawlik

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <windows.h>
#include <stdio.h>
#include "kafl_user.h"
#include "driver.h"
#include "kernel.h"

HANDLE kafl_vuln_handle;

void harness() {
	//kAFL_hypercallEx(HYPERCALL_KAFL_MEMWRITE, module_base_address + 0x15210, (uint64_t)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
	return;
}

char OutBuffer[0x10000];

int main(int argc, char** argv){
    hprintf("[+] Starting... %s", argv[0]);
	/* Patching ioctl filter */
	UINT64 psGetCurrentProcessId = 0x0;
    UINT64 psGetCurrentThreadId = 0x0;

	psGetCurrentProcessId = resolve_KernelFunction(sPsGetCurrentProcessId);
	*(uint32_t*)(ioctl_filter_bypass + 1) = GetCurrentProcessId();
	kAFL_hypercallEx(HYPERCALL_KAFL_MEMWRITE, psGetCurrentProcessId + 0x10, (uint64_t)ioctl_filter_bypass, sizeof(ioctl_filter_bypass));

	psGetCurrentThreadId = resolve_KernelFunction(sPsGetCurrentThreadId);
	*(uint32_t*)(ioctl_filter_bypass + 1) = GetCurrentThreadId();
	kAFL_hypercallEx(HYPERCALL_KAFL_MEMWRITE, psGetCurrentThreadId + 0x10, (uint64_t)ioctl_filter_bypass, sizeof(ioctl_filter_bypass));

	// Overwrite ticks of system timer.
	//kAFL_hypercallEx(HYPERCALL_KAFL_MEMWRITE, 0xFFFFF78000000320, (uint64_t)aaa, sizeof(aaa));

    hprintf("[+] Allocating buffer for kAFL_payload struct");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE + 0x1000, MEM_COMMIT, PAGE_READWRITE);

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)", (uint64_t) payload_buffer, PAYLOAD_SIZE + 0x1000);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE + 0x1000);

	/* submit the guest virtual address of the payload buffer */
    hprintf("[+] Submitting buffer address to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */ 
    hprintf("[+] Submitting current CR3 value to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	// Register the driver.
    create_service();
    load_driver();

	kafl_vuln_handle = open_driver_device();
	if (!kafl_vuln_handle)
		kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);

	if (!set_ip0_filter()) {
		hprintf("[+] Fail to set ip0 filter.");
		return 0;
	}

	while(1) {
		harness();
		
		while(1){
				kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
				if (payload_buffer->IoControlCode <= MAX_INST_COUNT)
					break;
				/* request new payload (*blocking*) */
				kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
				
				/* kernel fuzzing */
				//hprintf("%x %16s", payload_buffer->IoControlCode, &payload_buffer->InBuffer);
				DeviceIoControl(kafl_vuln_handle,
					payload_buffer->IoControlCode,
					&payload_buffer->InBuffer,
					payload_buffer->InBufferLength,
					OutBuffer,
					payload_buffer->OutBufferLength,
					NULL,
					NULL
				);

				/* inform fuzzer about finished fuzzing iteration */
				//hprintf("[+] Injection finished...");
				kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		}

		/* Execute a command from fuzzer.*/
		uint32_t cmd = payload_buffer->IoControlCode;
		switch (cmd) {
        case AGENT_EXIT:
            kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
			return 0;
		case DRIVER_REVERT:
			kAFL_hypercallEx(HYPERCALL_KAFL_IP_FILTER, 0, 0, 0);
			break;
		case DRIVER_RELOAD:
			CloseHandle(kafl_vuln_handle);
			if (!unload_driver() || !load_driver())
				kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
			
			kafl_vuln_handle = open_driver_device();
			if (!kafl_vuln_handle)
				kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);

			if (!set_ip0_filter()) {
				hprintf("[+] Fail to set ip0 filter.");
				kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
			}
			break;
		}
	}
    return 0;
}

