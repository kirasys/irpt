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

/* Driver and agent file */
#include "driver.h"
LPCSTR AGENTPATH = "C:\\Users\\kirasys\\Desktop\\agent.exe";

/* get KeBugCheck */
/* -------------- */

#include <psapi.h>
#define ARRAY_SIZE 1024

PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}


/* force termination on AVs */
void WINAPI nuke(){
    TerminateProcess((HANDLE)-1, 0x41);
}


LONG CALLBACK catch_all(struct _EXCEPTION_POINTERS *ExceptionInfo) {
    ExceptionInfo->ContextRecord->Rip = (DWORD64)nuke;
    return EXCEPTION_CONTINUE_EXECUTION; // return -1;
}


UINT64 resolve_KeBugCheck(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck){
                        printf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else{
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64) KeBugCheck;
}
/* -------------- */

static inline void run_program(char* target){
    PROCESS_INFORMATION p1;
    STARTUPINFOA s1;

        ZeroMemory(&p1, sizeof(p1));
        ZeroMemory(&s1, sizeof(s1));
        s1.cb = sizeof(s1);

        printf("[+] LOADER: Starting fuzzing target\n");
        BOOL success = CreateProcessA(NULL, target, NULL, NULL, FALSE,
            0, NULL, NULL, &s1, &p1);
        if (!success){
            printf("[-] LOADER: cannot start fuzzing target\n");
            getchar();
            ExitProcess(0);
        }
        TerminateProcess((HANDLE)-1,0x41);
}

static inline DWORD create_program(char* buf, LPCSTR path){
    DWORD program_size = *(DWORD*)buf;
    HANDLE payload_file_handle = NULL;
    DWORD dwWritten;

    payload_file_handle = CreateFile(path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    BOOL result = WriteFile(
        payload_file_handle,
        (LPCVOID)(buf + 4),
        program_size,
        &dwWritten,
        NULL
    );
    if (result == 0){
        printf("[+] Cannot write usermode fuzzer (%ld)\n", GetLastError());
        /* blocks */
        getchar();
    }

    printf("[+] LOADER: Create target : %s\n", path);
    CloseHandle(payload_file_handle);

    return program_size;
}

static inline void load_programs(char* buf){
    // Create a target driver.
    DWORD driver_size = create_program(buf, DRIVERPATH);

    // Run an target agent.
    create_program(buf + driver_size + sizeof(DWORD), AGENTPATH);
    run_program((char*)AGENTPATH);
}

static inline UINT64 hex_to_bin(char* str){
    return (UINT64)strtoull(str, NULL, 16);
}

int main(int argc, char** argv){
    UINT64 panic_handler1 = 0x0;
    UINT64 panic_handler2 = 0x0;
    void* program_buffer;

    if (AddVectoredExceptionHandler(1, catch_all) == 0){
        printf("[+] Cannot add veh handler %u\n", (UINT32)GetLastError());
		ExitProcess(0);
    }


    panic_handler1 = resolve_KeBugCheck(kernel_func1);
    panic_handler2 = resolve_KeBugCheck(kernel_func2);

    /* allocate 4MB contiguous virtual memory to hold fuzzer program; data is provided by the fuzzer */
    program_buffer = (void*)VirtualAlloc(0, PROGRAM_SIZE, MEM_COMMIT, PAGE_READWRITE);
    /* ensure that the virtual memory is *really* present in physical memory... */
    memset(program_buffer, 0xff, PROGRAM_SIZE);

    /* this hypercall will generate a VM snapshot for the fuzzer and subsequently terminate QEMU */
    kAFL_hypercall(HYPERCALL_KAFL_SNAPSHOT, 0);

    /***** Fuzzer Entrypoint *****/
    //kAFL_hypercall(HYPERCALL_KAFL_PRINTF, "Fuzzing start");
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    /* initial fuzzer handshake */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler1);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler2);
    /* submit virtual address of program buffer and wait for data (*blocking*) */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PROGRAM, (UINT64)program_buffer);
    /* execute fuzzer program */
    load_programs((char*)program_buffer);
    /* bye */ 
    return 0;
}
