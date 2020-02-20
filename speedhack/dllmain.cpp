// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <cstdio>

// All information regarding PEs (EXEs) can be found here:
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Imports_and_Exports_-_Linking_to_other_modules
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

// Note: RVAs are addresses (offsets) relative to the base address of the module.

double GTC_SPEED_FACTOR = 2.0;
double QPC_SPEED_FACTOR = 2.0;
LARGE_INTEGER initial_performance_counter;  // For QueryPerformanceCounter


DWORD get_PE_header_address()
{
	// This is simply the start of the EXE (always). This is different from the 
	// DLL address.
	return (DWORD)GetModuleHandle(NULL);
}

DWORD validate_IAT_integrity(DWORD base_adr)
{
	// Each Windows EXE starts with this magic number.
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base_adr;
	if (dos_header->e_magic != 0x5A4D) {
		return 0;
	}
	// "Every image file has an optional header that provides information to the loader."
	// The magic number determines if this is a PE32 executable (as opposed to a 64-bit PE32+).
	IMAGE_OPTIONAL_HEADER* opt_header = (IMAGE_OPTIONAL_HEADER*)(base_adr + 
		dos_header->e_lfanew + 24);
	if (opt_header->Magic != 0x10B) {
		return 0;
	}

	// Now, we make sure the IAT is intact.
	IMAGE_DATA_DIRECTORY IAT = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (IAT.Size == 0 || IAT.VirtualAddress == 0) {
		return 0;
	}

	return base_adr + IAT.VirtualAddress;
}

// Perform an Import Address Table hook. 
// In the table replace the function named 'fname' to point to 'new_func'.
// On success return the replaced address in the IAT. NULL otherwise.
DWORD IAT_hook(const char* fname, DWORD new_func)
{
	DWORD base_adr = get_PE_header_address();
	DWORD iat_adr = validate_IAT_integrity(base_adr);
	printf("%x %x\n", base_adr, iat_adr);
	if (iat_adr == 0) {
		return NULL;
	}

	// Now we can traverse the IAT. The IAT is an array of IMAGE_IMPORT_DESCRIPTORs.
	// Each IMAGE_IMPORT_DESCRIPTOR points to an import address table (IAT) of IMAGE_THUNK_DATAs.
	// Arrays are terminated by an all null element.
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)iat_adr;
	while (import_descriptor->FirstThunk != NULL) {
		printf("%s\n", (char*)(import_descriptor->Name + base_adr));
		
		// Each thunk is a union. 
		// There are 2 arrays: OriginalFirstThunk and FirstThunk.
		// OriginalFirstThunk contains RVAs of IMAGE_IMPORT_BY_NAME structures, which contain
		// the name of each function.
		// FirstThunk contains function pointers.
		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(import_descriptor->OriginalFirstThunk + base_adr);
		int n = 0;
		while (thunk->u1.Function != NULL) {
			char* imported_function_name = (char*)(base_adr + (DWORD)(thunk->u1.AddressOfData) + sizeof(WORD));
			printf("\t%d. %s\n", n + 1, imported_function_name);
			if (strcmp(fname, imported_function_name) == 0) {
				DWORD* ftable = (DWORD*)(base_adr + import_descriptor->FirstThunk);
				DWORD old_func = ftable[n];

				DWORD old_protection;
				VirtualProtect(&ftable[n], sizeof(DWORD), PAGE_READWRITE, &old_protection);
				ftable[n] = new_func;
				VirtualProtect(&ftable[n], sizeof(DWORD), old_protection, &old_protection);

				return old_func;
			}
			++n;
			++thunk;
		}
		import_descriptor++;
	}
	return NULL;
}

DWORD __stdcall my_GetTickCount()
{
	static DWORD initial_time = GetTickCount();
	// printf("my_GetTickCount\n");
	return initial_time + (DWORD)((GetTickCount() - initial_time) * GTC_SPEED_FACTOR);
}

BOOL __stdcall my_QueryPerfomanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	LARGE_INTEGER pc;
	BOOL res = QueryPerformanceCounter(&pc);
	lpPerformanceCount->QuadPart = initial_performance_counter.QuadPart + 
		(LONGLONG)((pc.QuadPart - initial_performance_counter.QuadPart) * QPC_SPEED_FACTOR);
	return res;
}

void hook_GetTickCount(double speed_factor)
{
	printf("HOOKING GetTickCount\n");
	GTC_SPEED_FACTOR = speed_factor;
	if (IAT_hook("GetTickCount", (DWORD)(&my_GetTickCount))) {
		printf("Success GTC!\n");
	} else {
		printf("Failure GTC!\n");
	}
}

void hook_QueryPerformanceCounter(double speed_factor)
{
	printf("HOOKING QueryPerformanceCounter\n");
	QPC_SPEED_FACTOR = speed_factor;
	QueryPerformanceCounter(&initial_performance_counter);
	if (IAT_hook("QueryPerformanceCounter", (DWORD)(&my_QueryPerfomanceCounter))) {
		printf("Success QPC!\n");
	}
	else {
		printf("Failure QPC!\n");
	}
}

void WINAPI speedhack(HMODULE dll)
{
	printf("Hello, world!\n");
	// hook_GetTickCount(2.0);
	hook_QueryPerformanceCounter(5.0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		HANDLE thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&speedhack, hModule, NULL, NULL);
		CloseHandle(thread);
	}
    return TRUE;
}

