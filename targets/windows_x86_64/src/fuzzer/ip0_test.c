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

LPCSTR SVCNAME = "toy";
LPCSTR DRIVERNAME = "toy_driver.sys";
LPCSTR DRIVERPATH = "C:\\Users\\kirasys\\Desktop\\toy_driver.sys";

#include <psapi.h>
#include <winternl.h>
#define ARRAY_SIZE 1024

PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func = "PsCreateSystemThread";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function) {
	HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
	return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


int create_service() {
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scmHandle) {
		puts("[create_service] OpenSCManager error!");
		return 0;
	}

	CreateServiceA(scmHandle, SVCNAME, SVCNAME,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DRIVERPATH,
		NULL, NULL, NULL, NULL, NULL);
	
	CloseServiceHandle(scmHandle);
	return 1;
}

int load_driver() {
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmHandle) {
		puts("[load_driver] OpenSCManager error!");
		return 0;
	}

	SC_HANDLE schService = OpenServiceA(
		scmHandle,       // SCM database 
		SVCNAME,          // name of service 
		SERVICE_START);
	if (!schService) {
		CloseServiceHandle(scmHandle);
		puts("[load_driver] OpenServiceA error!");
		return 0;
	}

	// Start the service
	SERVICE_STATUS status = {};
	if (StartService(schService, 0, NULL)) {
		while (QueryServiceStatus(schService, &status)) {
			if (status.dwCurrentState != SERVICE_START_PENDING)
				break;
			Sleep(500);
		}
	}
	else
		puts("[load_driver] StartService error!");

	CloseServiceHandle(schService);
	CloseServiceHandle(scmHandle);
	return 1;
}


int unload_driver() {
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmHandle) {
		puts("[unload_driver] OpenSCManager error!");
		return 0;
	}

	SC_HANDLE schService = OpenServiceA(
		scmHandle,       // SCM database 
		SVCNAME,          // name of service 
		SERVICE_STOP);
	if (!schService) {
		CloseServiceHandle(scmHandle);
		puts("[unload_driver] OpenServiceA error!");
		return 0;
	}

	SERVICE_STATUS status = {};
	if (ControlService(schService, SERVICE_CONTROL_STOP, &status)) {
		while (QueryServiceStatus(schService, &status)) {
			if (status.dwCurrentState != SERVICE_START_PENDING)
				break;
			Sleep(500);
		}
	}
	else
		puts("[unload_driver] ControlService error!");
	
	CloseServiceHandle(schService);
	CloseServiceHandle(scmHandle);
	return 1;
}

void set_ip0_filter() {
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;
	int cDrivers, i;
	NTSTATUS status;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[ARRAY_SIZE];

		cDrivers = cbNeeded / sizeof(drivers[0]);
		PRTL_PROCESS_MODULES ModuleInfo;

		ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!ModuleInfo) {
			goto fail;
		}

		if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL))) {
			VirtualFree(ModuleInfo, 0, MEM_RELEASE);
			goto fail;
		}

		for (i = 0; i < cDrivers; i++) {
			PCHAR driver_filename = (PCHAR)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName;
			if (!strcmp(driver_filename, DRIVERNAME)) {
                hprintf("[+] Set ip0 filter.");
				kAFL_hypercallEx(HYPERCALL_KAFL_IP_FILTER, drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize);
				break;
			}
		}
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	}

fail:
	return;
}

int main(int argc, char** argv){
    hprintf("[+] Starting... %s", argv[0]);

    hprintf("[+] Allocating buffer for kAFL_payload struct");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    /* open vulnerable driver */
    create_service();
    load_driver();

    HANDLE kafl_vuln_handle = INVALID_HANDLE_VALUE;
    hprintf("[+] Attempting to open vulnerable device file (%s)", "\\\\.\\toy");
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\toy",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("[-] Cannot get device handle: 0x%X", GetLastError());
        return 0;
    }

    /* submit the guest virtual address of the payload buffer */
    hprintf("[+] Submitting buffer address to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */ 
    hprintf("[+] Submitting current CR3 value to hypervisor...");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
    
    /* set ip0 filter */
    set_ip0_filter();
    while(1){
            kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
            /* request new payload (*blocking*) */
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
            
            /* kernel fuzzing */
            hprintf("[+] Injecting data...");
            DeviceIoControl(kafl_vuln_handle,
                *(DWORD*)(payload_buffer->data),
                (LPVOID)(payload_buffer->data + 4),
                (DWORD)payload_buffer->size - 4,
                NULL,
                0,
                NULL,
                NULL
            );

            /* inform fuzzer about finished fuzzing iteration */
            hprintf("[+] Injection finished...");
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    return 0;
}

