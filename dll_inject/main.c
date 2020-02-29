#include "dll_inject.h"
#include <stdio.h>

const char* HELP_STR = "dll_inject <PID> <DLL> [u]";

int main(int argc, char* argv[]) 
{
	if (argc < 3) {
		printf("%s\n", HELP_STR);
		return 0;
	}

	DWORD pid = atol(argv[1]);
	const char* dll_path = argv[2];
	HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc_handle == NULL) {
		printf("Cannot open process... %lu %s\n", pid, dll_path);
		return 0;
	}

	if (argc >= 4 && argv[3][0] == 'u') {
		if (unload_dll_by_name(proc_handle, dll_path)) {
			printf("DLL unloading successful %s\n", dll_path);
		}
		else {
			printf("Error unloading dll %s\n", dll_path);
		}
	}
	else {
		HMODULE dll = load_dll(proc_handle, dll_path);
		if (dll == NULL) {
			printf("Error loading dll %s\n", dll_path);
		}
		else {
			printf("DLL loading successful %s --> %x\n", dll_path, dll);
		}
	}

	CloseHandle(proc_handle);

    return 0;
}
