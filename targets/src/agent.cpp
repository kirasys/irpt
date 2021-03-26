/*
 * Copyright 2020 Namjun Jo (kirasys@theori.io)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <windows.h>
#include <stdio.h>
#include "irpt_user.h"
#include "driver.h"
#include "kernel.h"

HANDLE device_handle;

void harness(void) {
	//HypercallEx(HYPERCALL_IRPT_MEMWRITE, module_base_address + 0x15210, (uint64_t)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
	return;
}

char BigInputBuffer[0x800000];
char OutputBuffer[0x10000];

int main(int argc, char** argv){
	UINT64 psGetCurrentProcessId;
	UINT64 psGetCurrentThreadId;

    hprintf("[+] Starting... %s", argv[0]);

    hprintf("[+] Allocating buffer for IRPT_payload struct");
    IRPT_payload* payload_buffer = (IRPT_payload*)VirtualAlloc(0, PAYLOAD_SIZE + 0x1000, MEM_COMMIT, PAGE_READWRITE);

    hprintf("[+] Memset IRPT_payload at address %lx (size %d)", (uint64_t) payload_buffer, PAYLOAD_SIZE + 0x1000);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE + 0x1000);

	/* submit the guest virtual address of the payload buffer */
    hprintf("[+] Submitting buffer address to hypervisor...");
    Hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */ 
    hprintf("[+] Submitting current CR3 value to hypervisor...");
    Hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	// Register the driver.
	delete_service();
    create_service();
    load_driver();

	device_handle = open_driver_device();
	if (!device_handle)
		Hypercall(HYPERCALL_KAFL_USER_ABORT, 0);

	if (!set_ip0_filter()) {
		hprintf("[+] Fail to set ip0 filter.");
		return 0;
	}

	while(1) {
		harness();
		
		while(1){
			Hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

			uint32_t cmd = payload_buffer->Command;
			switch (cmd) {
			case EXECUTE_IRP:
				/* request new payload (*blocking*) */
				Hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
				//hprintf("%x %x", payload_buffer->IoControlCode, payload_buffer->InBufferLength);

				DeviceIoControl(device_handle,
					payload_buffer->IoControlCode,
					payload_buffer->InBuffer,
					payload_buffer->InBufferLength,
					OutputBuffer,
					payload_buffer->OutBufferLength,
					NULL,
					NULL
				);

				/* inform fuzzer about finished fuzzing iteration */
				Hypercall(HYPERCALL_KAFL_RELEASE, 0);
				break;
			case DRIVER_REVERT:
				HypercallEx(HYPERCALL_IRPT_IP_FILTER, 0, 0, 0);
				break;
			case DRIVER_RELOAD:
				CloseHandle(device_handle);
				if (!unload_driver() || !load_driver())
					Hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
				
				device_handle = open_driver_device();
				if (!device_handle)
					Hypercall(HYPERCALL_KAFL_USER_ABORT, 0);

				if (!set_ip0_filter()) {
					hprintf("[+] Fail to set ip0 filter.");
					Hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
				}
				break;
			case CHECK_PAGE_FAULT:
				memset(BigInputBuffer, 0x61, sizeof(BigInputBuffer));
				memcpy(BigInputBuffer, payload_buffer->InBuffer, payload_buffer->InBufferLength);
				
				/* request new payload (*blocking*) */
				Hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

				DeviceIoControl(device_handle,
					payload_buffer->IoControlCode,
					BigInputBuffer,
					sizeof(BigInputBuffer),
					OutputBuffer,
					payload_buffer->OutBufferLength,
					NULL,
					NULL
				);

				/* inform fuzzer about finished fuzzing iteration */
				Hypercall(HYPERCALL_KAFL_RELEASE, 0);
				break;
			case ANTI_IOCTL_FILTER:
				psGetCurrentProcessId = resolve_KernelFunction(sPsGetCurrentProcessId);
				psGetCurrentThreadId = resolve_KernelFunction(sPsGetCurrentThreadId);

				*(uint32_t*)(ioctl_filter_bypass + 1) = GetCurrentProcessId();
				HypercallEx(HYPERCALL_IRPT_MEMWRITE, psGetCurrentProcessId + 0x10, (uint64_t)ioctl_filter_bypass, sizeof(ioctl_filter_bypass));
				*(uint32_t*)(ioctl_filter_bypass + 1) = GetCurrentThreadId();
				HypercallEx(HYPERCALL_IRPT_MEMWRITE, psGetCurrentThreadId + 0x10, (uint64_t)ioctl_filter_bypass, sizeof(ioctl_filter_bypass));
				break;
			}
		}
	}
    return 0;
}

