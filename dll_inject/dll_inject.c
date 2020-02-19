#include "dll_inject.h"
#include "Windows.h"
#include <stdio.h>
#include "psapi.h"

HMODULE load_dll(HANDLE proc, const char* dll_path) 
{
	// write the dll path to process memory 
	size_t path_len = strlen(dll_path) + 1;
	LPVOID remote_string_address = VirtualAllocEx(proc, NULL, path_len, MEM_COMMIT, PAGE_EXECUTE);
	WriteProcessMemory(proc, remote_string_address, dll_path, path_len, NULL);

	// get the address of the LoadLibrary()
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	LPVOID load_library_adr = GetProcAddress(k32, "LoadLibraryA");

	// create the thread
	HANDLE thread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)load_library_adr, remote_string_address, NULL, NULL);

	// finish and clean up
	WaitForSingleObject(thread, INFINITE);

	DWORD dll_handle;
	GetExitCodeThread(thread, &dll_handle);

	CloseHandle(thread);

	VirtualFreeEx(proc, remote_string_address, path_len, MEM_RELEASE);

	return (HMODULE)dll_handle;
}


void unload_dll(HANDLE proc, HMODULE dll_handle) 
{
	// get the address of FreeLibrary()
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	LPVOID free_library_adr = GetProcAddress(k32, "FreeLibrary");

	HANDLE thread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)free_library_adr, dll_handle, NULL, NULL);

	WaitForSingleObject(thread, INFINITE);

	DWORD exit_code;
	GetExitCodeThread(thread, &exit_code);

	CloseHandle(thread);
}

const char* HELP_STR = "inject <PID> <DLL>";

int main(int argc, char* argv[]) 
{
	if (argc < 3) {
		printf("%s\n", HELP_STR);
		return 0;
	}

	DWORD pid = atoll(argv[1]);
	HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc_handle == NULL) {
		printf("Cannot open process... %lu %s\n", pid, argv[2]);
		return 0;
	}
	else {
		printf("%x %s\n", proc_handle, argv[2]);
	}

	HMODULE dll = load_dll(proc_handle, argv[2]);
	printf("%x\n", dll);
	CloseHandle(proc_handle);

    return 0;
}