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

HANDLE kafl_vuln_handle;

void harness() {
	return;
}

char OutBuffer[0x10000];

int main(int argc, char** argv){
    hprintf("[+] Starting... %s", argv[0]);

    hprintf("[+] Allocating buffer for kAFL_payload struct");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

	/* submit the guest virtual address of the payload buffer */
    hprintf("[+] Submitting buffer address to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */ 
    hprintf("[+] Submitting current CR3 value to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	kafl_vuln_handle = open_driver();
	if (!kafl_vuln_handle)
		return 0;
	harness();

	if (!set_ip0_filter()) {
		hprintf("[+] Fail to set ip0 filter.");
		return 0;
	}
	
	while(1) {
		/* set ip0 filter */
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
            return 0;
		case DRIVER_REVERT:
			kAFL_hypercallEx(HYPERCALL_KAFL_IP_FILTER, 0, 0);
			break;
		case DRIVER_RELOAD:
			CloseHandle(kafl_vuln_handle);
			if (!unload_driver() || !load_driver())
				return 0;
			
			kafl_vuln_handle = open_driver();
			if (!kafl_vuln_handle)
				return 0;
			harness();

			if (!set_ip0_filter()) {
				hprintf("[+] Fail to set ip0 filter.");
				return 0;
			}
			break;
		}
	}
    return 0;
}

