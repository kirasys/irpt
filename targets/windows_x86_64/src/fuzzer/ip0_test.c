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
#include <psapi.h>
#include <stdio.h>
#include "kafl_user.h"

LPCSTR SVCNAME = "toy";
LPCSTR DRIVERNAME = "toy_driver.sys";
LPCSTR DRIVERPATH = "C:\\Users\\namjunjo\\Downloads\\toy_driver.sys";

HANDLE kafl_vuln_handle = INVALID_HANDLE_VALUE;

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

int set_ip0_filter() {

}

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

    
    while (1) {
        if (!load_driver()) {
            puts("load_driver error");
            return 0;
        }
        if(!set_ip0_filter()) {
            puts("set_ip0_filter error");
            return 0;
        }
        /* open vulnerable driver */
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
    
        while(1){
                /* request new payload (*blocking*) */
                kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
                if (payload_buffer->action == RELOAD_DRIVER)
                    break;
                
                /* enable pt trace */
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
        unload_driver();
    }
    return 0;
}

