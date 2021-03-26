/*
 * Copyright 2020 Namjun Jo (kirasys@theori.io)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <windows.h>
#include <psapi.h>

PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR sPsGetCurrentProcessId = "PsGetCurrentProcessId";
PCSTR sPsGetCurrentThreadId = "PsGetCurrentThreadId";
PCSTR sKeBugCheck = "KeBugCheck";
PCSTR sKeBugCheckEx = "KeBugCheckEx";

/*
0: 3d 61 61 61 61   cmp eax, 0x61616161
5: 75 03            jne RET
7: 48 31 c0         xor rax, rax
RET:
a: c3               ret
*/
uint8_t ioctl_filter_bypass[] = "\x3d\x61\x61\x61\x61\x75\x03\x48\x31\xc0\xc3";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}

UINT64 resolve_KernelFunction(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC func = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    func = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!func){
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

    return  (UINT64) func;
}