LPCSTR SVCNAME = "toy";
LPCSTR DRIVERNAME = "toy_driver.sys";
LPCSTR DRIVERPATH = "C:\\Users\\kirasys\\Desktop\\toy_driver.sys";
LPCSTR DRIVER_SVCPATH = "\\\\.\\toy";
/*
LPCSTR SVCNAME = "medcored";
LPCSTR DRIVERNAME = "medcored.sys";
LPCSTR DRIVERPATH = "C:\\Users\\kirasys\\Desktop\\medcored.sys";
LPCSTR DRIVER_SVCPATH = "\\\\.\\medcored";
*/

#include <psapi.h>
#include <winternl.h>
#define ARRAY_SIZE 1024
#define MAX_INST_COUNT 5

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


bool create_service() {
    bool success;
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scmHandle) {
		hprintf("[create_service] OpenSCManager error!");
		return false;
	}

	success = CreateServiceA(scmHandle, SVCNAME, SVCNAME,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DRIVERPATH,
		NULL, NULL, NULL, NULL, NULL);
	
	CloseServiceHandle(scmHandle);
	return success;
}

bool load_driver() {
    bool success = true;
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scmHandle) {
		hprintf("[load_driver] OpenSCManager error!");
		return false;
	}

	SC_HANDLE schService = OpenServiceA(
		scmHandle,       // SCM database 
		SVCNAME,          // name of service 
		SERVICE_ALL_ACCESS);
	if (!schService) {
		CloseServiceHandle(scmHandle);
		hprintf("[load_driver] OpenServiceA error!");
		return false;
	}

	// Start the service
	if (StartService(schService, 0, NULL) == 0) {
        hprintf("[load_driver] StartService error!");
        success = false;
    }

	CloseServiceHandle(schService);
	CloseServiceHandle(scmHandle);
	return success;
}


bool unload_driver() {
    bool success = true;
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scmHandle) {
		hprintf("[unload_driver] OpenSCManager error!");
		return false;
	}

	SC_HANDLE schService = OpenServiceA(
		scmHandle,       // SCM database 
		SVCNAME,          // name of service 
		SERVICE_ALL_ACCESS);
	if (!schService) {
		CloseServiceHandle(scmHandle);
		hprintf("[unload_driver] OpenServiceA error!");
		return false;
	}
	
	SERVICE_STATUS status = {};
	if (ControlService(schService, SERVICE_CONTROL_STOP, &status) == 0) {
		hprintf("[unload_driver] ControlService error!");
        success = false;
    }

	CloseServiceHandle(schService);
	CloseServiceHandle(scmHandle);
	return success;
}

HANDLE open_driver() {
	HANDLE kafl_vuln_handle = INVALID_HANDLE_VALUE;
	hprintf("[+] Attempting to open vulnerable device file (%s)", DRIVER_SVCPATH);
	kafl_vuln_handle = CreateFile(DRIVER_SVCPATH,
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
	return kafl_vuln_handle;
}

bool set_ip0_filter() {
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;
	int cDrivers, i;
	NTSTATUS status;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		cDrivers = cbNeeded / sizeof(drivers[0]);
		PRTL_PROCESS_MODULES ModuleInfo;

		ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!ModuleInfo)
			return false;

		if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL))) {
			VirtualFree(ModuleInfo, 0, MEM_RELEASE);
			return false;
		}

		for (i = 0; i < cDrivers; i++) {
			PCHAR driver_filename = (PCHAR)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName;
			if (!strcmp(driver_filename, DRIVERNAME)) {
				hprintf("[+] Set ip0 filter.");
				kAFL_hypercallEx(HYPERCALL_KAFL_IP_FILTER, (UINT64)drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize);
				break;
			}
		}
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	}

	return true;
}