#include "windows.h"
#include <stdio.h>
#include "../dll_inject/dll_inject.h"

typedef void(__stdcall *p_api_set_speed)(float);
const char* API_SET_SPEED_NAME = "_api_set_speed@4";  // function export name (see speedhack.dll)
p_api_set_speed f_api_set_speed;

// Call procedure at 'proc_adr' in the target process.
// If the function takes an argument of size 4/8 bytes you can 
// pass it in directly as 'params'. Otherwise, the parameters
// must be allocated and written in the target process and 'params'
// should then point to that memory location.
DWORD call_procedure(HANDLE process, DWORD proc_adr, void* params)
{
	HANDLE thread = CreateRemoteThread(process, NULL, NULL, proc_adr, params, NULL, NULL);
	WaitForSingleObject(thread, INFINITE);
	DWORD ret;
	GetExitCodeThread(thread, &ret);
	CloseHandle(thread);
	return ret;
}

DWORD get_proc_address(HANDLE process, HMODULE dll_handle, const char* name)
{
	// Idea: create a code cave that will call GetProcAddress.	

	BYTE shellcode[] = {
		0xFF, 0x74, 0x24, 0x04,			// PUSH DWORD PTR:[ESP+0x4] ('name' from CreateRemoteThread)
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH dll_handle
		0xB8, 0x00, 0x00, 0x00, 0x00,	// MOV EAX, GetProcAddress
		0xFF, 0xD0,						// CALL EAX
		0xC3							// RETN
	};

	HMODULE k32 = GetModuleHandle("kernel32.dll");
	LPVOID get_proc_adr = GetProcAddress(k32, "GetProcAddress");

	// Fill in the gaps in the shellcode with the dll_handle and GetProcAddress.
	memcpy(&shellcode[5], &dll_handle, 4);
	memcpy(&shellcode[10], &get_proc_adr, 4);

	DWORD name_len = strlen(name) + 1;
	DWORD cave_size = sizeof(shellcode) + name_len;
	LPVOID cave_adr = VirtualAllocEx(process, NULL, cave_size, MEM_COMMIT, PAGE_EXECUTE);
	DWORD code_adr = (DWORD)cave_adr + name_len;
	// Write the procedure name and the shellcode into the allocated code cave.
	WriteProcessMemory(process, cave_adr, name, name_len, NULL);
	WriteProcessMemory(process, code_adr, shellcode, sizeof(shellcode), NULL);

	DWORD ret = call_procedure(process, code_adr, cave_adr);

	VirtualFreeEx(process, cave_adr, cave_size, MEM_RELEASE);

	return ret;
}

DWORD get_dll_handle(HANDLE process, const char* dll)
{
	// Get the dll handle from the target process (GetModuleHandle).
	// The handle is valid only 'inside' the target process.
	// Then use the returned handle to unload the dll (FreeLibrary) in the target process.
	
	// Write the dll path to target process memory.
	size_t path_len = strlen(dll) + 1;
	LPVOID remote_string_address = VirtualAllocEx(process, NULL, path_len, MEM_COMMIT, PAGE_EXECUTE);
	WriteProcessMemory(process, remote_string_address, dll, path_len, NULL);

	HMODULE k32 = GetModuleHandle("kernel32.dll");
	LPVOID get_module_handle_adr = GetProcAddress(k32, "GetModuleHandleA");
	DWORD dll_handle = call_procedure(process, get_module_handle_adr, remote_string_address);

	VirtualFreeEx(process, remote_string_address, path_len, MEM_RELEASE);
	return dll_handle;
}

void api_set_speed(HANDLE process, float factor)
{
	// Interpret the float bytes as a DWORD (instead of flooring the float).
	if (f_api_set_speed) {
		call_procedure(process, f_api_set_speed, *(DWORD*)(&factor));
	}
}

const char* HELP_STR = "speedhackAPI <DLL> <PID>";

int main(int argc, char* argv[])
{
	if (argc < 3) {
		printf("%s\n", HELP_STR);
		return 0;
	}

	const char* dll_path = argv[1];
	DWORD pid = atol(argv[2]);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process_handle == NULL) {
		printf("Cannot open process... %lu %s\n", pid, dll_path);
		return 0;
	}

	HMODULE dll_handle = load_dll(process_handle, dll_path);
	if (dll_handle == NULL) {
		printf("Error loading dll %s\n", dll_path);
	} else {
		printf("DLL loading successful %s --> %x\n", dll_path, dll_handle);
	}

	// HMODULE dll_handle = (HMODULE)get_dll_handle(process_handle, dll_path);
	f_api_set_speed = get_proc_address(process_handle, dll_handle, API_SET_SPEED_NAME);

	while (1) {
		float speed;
		if (scanf_s("%f", &speed)) {
			api_set_speed(process_handle, speed);
		} else {
			unload_dll_by_handle(process_handle, dll_handle);
			break;
		}
	}
}