/*
 * Copyright 2020 Namjun Jo (kirasys@theori.io)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <windows.h>
#include <stdio.h>
#include "irpt_user.h"

/* Driver and agent file */
#include "driver.h"
LPCSTR AGENTPATH = "C:\\agent.exe";

/* Kernel functions */
#include "kernel.h"
#define ARRAY_SIZE 1024


/* force termination on AVs */
void WINAPI nuke(){
    TerminateProcess((HANDLE)-1, 0x41);
}


LONG CALLBACK catch_all(struct _EXCEPTION_POINTERS *ExceptionInfo) {
    ExceptionInfo->ContextRecord->Rip = (DWORD64)nuke;
    return EXCEPTION_CONTINUE_EXECUTION; // return -1;
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
    UINT64 keBugCheck = 0x0;
    UINT64 keBugCheckEx = 0x0;
    void* program_buffer;

    if (AddVectoredExceptionHandler(1, catch_all) == 0){
        printf("[+] Cannot add veh handler %u\n", (UINT32)GetLastError());
		ExitProcess(0);
    }
    keBugCheck = resolve_KernelFunction(sKeBugCheck);
    keBugCheckEx = resolve_KernelFunction(sKeBugCheckEx);

    /* allocate 4MB contiguous virtual memory to hold fuzzer program; data is provided by the fuzzer */
    program_buffer = (void*)VirtualAlloc(0, PROGRAM_SIZE, MEM_COMMIT, PAGE_READWRITE);
    /* ensure that the virtual memory is *really* present in physical memory... */
    memset(program_buffer, 0xff, PROGRAM_SIZE);

    /* this hypercall will generate a VM snapshot for the fuzzer and subsequently terminate QEMU */
    Hypercall(HYPERCALL_KAFL_SNAPSHOT, 0);

    /***** Fuzzer Entrypoint *****/
    //Hypercall(HYPERCALL_KAFL_PRINTF, "Fuzzing start");
    Hypercall(HYPERCALL_IRPT_LOCK, 0);

    /* initial fuzzer handshake */
    Hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    Hypercall(HYPERCALL_KAFL_RELEASE, 0);
    /* submit panic address */
    Hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, keBugCheck);
    Hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, keBugCheckEx);

    /* submit virtual address of program buffer and wait for data (*blocking*) */
    Hypercall(HYPERCALL_KAFL_GET_PROGRAM, (UINT64)program_buffer);
    /* execute fuzzer program */
    load_programs((char*)program_buffer);
    /* bye */ 
    return 0;
}

