// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <cstdio>
#include "win_console.h"
#include "tlhelp32.h"
#include <unordered_map>

// All information regarding PEs (EXEs) can be found here:
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Imports_and_Exports_-_Linking_to_other_modules
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

// A great tool for inspecting PE headers: Cheat Engine -> Memory View -> Tools -> Dissect PE headers.

// NOTE: dbghelp.dll
// CheatEngine uses symbol handler functions from the above library.

// Note: RVAs are addresses (offsets) relative to the base address of the module.

double SPEED_FACTOR = 2.0;
LARGE_INTEGER initial_performance_counter;  // For QueryPerformanceCounter

typedef DWORD(WINAPI *p_GetTickCount)();
typedef ULONGLONG(WINAPI *p_GetTickCount64)();
typedef BOOL(WINAPI *p_QueryPerformanceCounter)(LARGE_INTEGER * lpPerformanceCount);
typedef DWORD(WINAPI *p_timeGetTime)();

struct IATHookInfo {
	const char* function_name;			// Name of the function being hooked.
	const char* base_module_name;		// Name of the module which imports 'imported_module'.
	const char* imported_module_name;   // Name of the imported module, which contains 
										// the function being hooked.
	DWORD table_address;				// Address of table entry in which there is the function address.
	DWORD original_function;			// Address of the replaced function in the table.
	DWORD hooked_function;				// Address of the function which replaces the original function.
};

IATHookInfo GetTickCount_hook;
IATHookInfo GetTickCount64_hook;
IATHookInfo QueryPerfomanceCounter_hook;
IATHookInfo timeGetTime_hook;


void write_dword(DWORD adr, DWORD val)
{
	DWORD old_protection;
	VirtualProtect((LPVOID)adr, sizeof(DWORD), PAGE_READWRITE, &old_protection);
	*((DWORD*)(adr)) = val;
	VirtualProtect((LPVOID)adr, sizeof(DWORD), old_protection, &old_protection);
}

DWORD get_PE_header_address(const char* module_name = NULL)
{
	// This is simply the start of the EXE (always). This is different from the 
	// DLL address.
	return (DWORD)GetModuleHandleA(module_name);
}

void print_PE_sections(DWORD module_base_adr)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base_adr;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		// Uh-oh
		return;
	}
	IMAGE_NT_HEADERS* headers = (IMAGE_NT_HEADERS*)(dos_header->e_lfanew + module_base_adr);
	if (headers->Signature != IMAGE_NT_SIGNATURE) {
		// "PE00"
		return;
	}

	// Sections are immediately after the IMAGE_NT_HEADERS (i.e. after the Optional header).
	int number_of_sections = headers->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)
		((DWORD)(&headers->OptionalHeader) + headers->FileHeader.SizeOfOptionalHeader);

	char name[9]; 
	name[8] = '\0';
	for (int i = 0; i < number_of_sections; ++i, ++section_header) {
		memcpy(name, section_header->Name, sizeof(section_header->Name));
		printf("%s :: %x bytes @ %x \n", name, 
			section_header->Misc.VirtualSize, section_header->VirtualAddress);
	}
}

void print_PE_sections(const char* module_name = NULL)
{
	print_PE_sections(get_PE_header_address(module_name));
}

void print_PE_exports(DWORD module_base_adr)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base_adr;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		// Uh-oh
		return;
	}
	IMAGE_NT_HEADERS* headers = (IMAGE_NT_HEADERS*)(dos_header->e_lfanew + module_base_adr);
	if (headers->Signature != IMAGE_NT_SIGNATURE) {
		// "PE00"
		return;
	}

	IMAGE_OPTIONAL_HEADER* opt_header = &headers->OptionalHeader;
	if (opt_header->Magic != 0x10B) {
		return;
	}

	IMAGE_DATA_DIRECTORY dir_entry = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dir_entry.Size == 0 || dir_entry.VirtualAddress == 0) {
		return;
	}

	IMAGE_EXPORT_DIRECTORY* directory = (IMAGE_EXPORT_DIRECTORY*)(dir_entry.VirtualAddress + module_base_adr);
	// All exported symbol addresses are in the EAT. The index of each entry in the table is the ordinal.
	// Names of exported symbols are in the Name table (each entry points to a string).
	// The Ordinal table contains the index (ordinal) into the EAT for every symbol name.
	// To find the address of the symbol from a given name, find the name in the Name table
	// and use the found index to lookup the Ordinal table to find the index into the EAT.
	WORD* ordinals = (WORD*)(directory->AddressOfNameOrdinals + module_base_adr);
	DWORD* names = (DWORD*)(directory->AddressOfNames + module_base_adr);
	DWORD* EAT = (DWORD*)(directory->AddressOfFunctions + module_base_adr);  // Export Address Table
	DWORD EAT_size = directory->NumberOfFunctions;
	DWORD names_size = directory->NumberOfNames;
	printf("Export table: %s\n", (char*)(directory->Name + module_base_adr));
	for (int i = 0; i < names_size; ++i) {
		char* name = (char*)(names[i] + module_base_adr);
		WORD ordinal = ordinals[i];
		DWORD address = EAT[ordinal];  // TODO forwarding
		printf(" %d. %s -> %x EAT[%d]\n", i + 1, name, address, ordinal);
	}
}

DWORD validate_IAT_integrity(DWORD base_adr)
{
	if (base_adr == 0) return 0;

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
// IF module_name is given, only the functions in that dll will be scanned.
DWORD IAT_hook(IATHookInfo* hook_info)
{
	DWORD base_adr = get_PE_header_address(hook_info->base_module_name);
	DWORD iat_adr = validate_IAT_integrity(base_adr);
	// printf("%x %x\n", base_adr, iat_adr);
	if (iat_adr == 0) {
		return NULL;
	}

	// Now we can traverse the IAT. The IAT is an array of IMAGE_IMPORT_DESCRIPTORs.
	// Each IMAGE_IMPORT_DESCRIPTOR points to an import address table (IAT) of IMAGE_THUNK_DATAs.
	// Arrays are terminated by an all null element.
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)iat_adr;
	while (import_descriptor->FirstThunk != NULL) {
		char* module_name = (char*)(import_descriptor->Name + base_adr);
		// printf("%s %x\n", module_name, get_PE_header_address(module_name));
		// We can specify in which module the function is found (case-insensitive comparison) ...
		if (hook_info->imported_module_name != NULL && lstrcmpiA(module_name, hook_info->imported_module_name) != 0) {
			import_descriptor++;
			continue;
		}

		// If we wanted to, we could recursively go into each module_name ...
		
		// Each thunk is a union. 
		// There are 2 arrays: OriginalFirstThunk (Import Lookup Table) and FirstThunk (Import Address Table).
		// OriginalFirstThunk contains RVAs of IMAGE_IMPORT_BY_NAME structures, which contain
		// the name of each function.
		// FirstThunk contains function pointers.
		// OriginalFirstThunk array is the unbound array and FirstThunk the array after binding.

		// Note: It is possible for the IAT to exist, despite ILT being invalid. However, we are
		// hooking by name so we need to know the name in the ILT as well.
		// The ILT table could be avoided altogether if we used dbghelp.dll (e.g. SymFromAddr).
		if (import_descriptor->OriginalFirstThunk == NULL || import_descriptor->FirstThunk == NULL) {
			import_descriptor++;
			continue;
		}

		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(import_descriptor->OriginalFirstThunk + base_adr);
		int n = 0;
		while (thunk->u1.Function != NULL) {
			// If the highest bit is set, importing is done by ordinal (instead of by name).
			// We ignore such functions ...
			// 0x8000000000000000 for 64-bit
			if (thunk->u1.AddressOfData & 0x80000000) {
				++n;
				++thunk;
				continue;
			}

			// Hint/Name table lookup
			// NOTE: sometimes trying to read the name string results in an Access violation error!
			char* imported_function_name = (char*)(base_adr + (DWORD)(thunk->u1.AddressOfData) + sizeof(WORD));
			// printf("\t%d. %s\n", n + 1, imported_function_name);
			if (strcmp(hook_info->function_name, imported_function_name) == 0) {
				DWORD* ftable = (DWORD*)(base_adr + import_descriptor->FirstThunk);
				DWORD old_func = ftable[n];
				write_dword((DWORD)&ftable[n], hook_info->hooked_function);
				
				hook_info->imported_module_name = module_name;
				hook_info->function_name = imported_function_name;
				hook_info->original_function = old_func;
				hook_info->table_address = (DWORD)&ftable[n];

				return old_func;
			}
			++n;
			++thunk;
		}
		import_descriptor++;
	}
	return NULL;
}

DWORD IAT_hook_modules(IATHookInfo* hook_info)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);  // Must be done (see docs).
	char* mod_str = (char*)malloc(512);  // I don't care about freeing this memory ...
	size_t retval;
	if (Module32First(snapshot, &entry) == TRUE) {
		do {
			// printf("\n%ws %x\n", entry.szModule, entry.hModule);
			wcstombs_s(&retval, mod_str, 512, entry.szModule, _TRUNCATE);
			hook_info->base_module_name = mod_str;
			DWORD ret = IAT_hook(hook_info);
			if (ret) return ret;
		} while (Module32Next(snapshot, &entry));
	}
	return 0;
}

void print_hook_info(IATHookInfo* hook_info)
{
	printf("%s\n", hook_info->base_module_name ? hook_info->base_module_name : "<PROCESS>");
	printf(" %s :: %s\n", hook_info->imported_module_name, hook_info->function_name);
	printf(" IAT %x :: %x -> %x\n", hook_info->table_address, hook_info->original_function, hook_info->hooked_function);
}

int traverse_imported_symbols(std::unordered_map<std::string, DWORD>& map, const char* module = NULL, int depth = 0)
{
	if (module != NULL && map.find(module) != map.end()) return 0;

	DWORD base_adr = get_PE_header_address(module);
	DWORD iat_adr = validate_IAT_integrity(base_adr);
	if (iat_adr == 0) return 0;

	if (module != NULL) map.insert({ module, base_adr });

	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)iat_adr;
	while (import_descriptor->FirstThunk != NULL) {
		char* dll_name = (char*)(import_descriptor->Name + base_adr);
		for (int i = 0; i < depth; ++i) printf("  ");
		printf("%s %x\n", dll_name, get_PE_header_address(dll_name));
		if (!traverse_imported_symbols(map, dll_name, depth + 1) 
			|| import_descriptor->OriginalFirstThunk == NULL
			|| import_descriptor->FirstThunk == NULL) {
			import_descriptor++;
			continue;
		}
		
		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(import_descriptor->OriginalFirstThunk + base_adr);
		int n = 0;
		while (thunk->u1.Function != NULL) {
			if (thunk->u1.AddressOfData & 0x80000000 == 0) {
				char* imported_function_name = (char*)(base_adr + (DWORD)(thunk->u1.AddressOfData) + sizeof(WORD));
				DWORD* ftable = (DWORD*)(base_adr + import_descriptor->FirstThunk);
				map.insert({ imported_function_name, ftable[n] });
				for (int i = 0; i < depth; ++i) printf("  ");
				printf(" %d. %s %x\n", n + 1, imported_function_name, ftable[n]);
			}
			++n;
			++thunk;
		}
		import_descriptor++;
	}
	return 1;
}

void print_modules()
{
	// Iterate over all modules in this process.
	std::unordered_map<std::string, DWORD> map;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);  // Must be done (see docs).
	char mod_str[512];
	size_t retval;
	if (Module32First(snapshot, &entry) == TRUE) {
		do {
			printf("%ws %x\n", entry.szModule, entry.hModule);
			wcstombs_s(&retval, mod_str, 512, entry.szModule, _TRUNCATE);
			traverse_imported_symbols(map, mod_str, 1);
			print_PE_exports(get_PE_header_address(mod_str));
		} while (Module32Next(snapshot, &entry));
	}
}

DWORD __stdcall my_GetTickCount()
{
	static p_GetTickCount func = (p_GetTickCount)GetTickCount_hook.original_function;
	static DWORD initial_time = func();
	return initial_time + (DWORD)((func() - initial_time) * SPEED_FACTOR);
}

ULONGLONG __stdcall my_GetTickCount64()
{
	static p_GetTickCount64 func = (p_GetTickCount64)GetTickCount64_hook.original_function;
	static ULONGLONG initial_time = func();
	return initial_time + (ULONGLONG)((func() - initial_time) * SPEED_FACTOR);
}

BOOL __stdcall my_QueryPerfomanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	static p_QueryPerformanceCounter func = (p_QueryPerformanceCounter)QueryPerfomanceCounter_hook.original_function;
	LARGE_INTEGER pc;
	BOOL res = func(&pc);
	lpPerformanceCount->QuadPart = initial_performance_counter.QuadPart + 
		(LONGLONG)((pc.QuadPart - initial_performance_counter.QuadPart) * SPEED_FACTOR);
	return res;
}

DWORD __stdcall my_timeGetTime()
{
	static p_timeGetTime func = (p_timeGetTime)timeGetTime_hook.original_function;
	static DWORD initial_time = func();
	return initial_time + (DWORD)((func() - initial_time) * SPEED_FACTOR);
}

void hook_GetTickCount(double speed_factor)
{
	printf("HOOKING GetTickCount\n");
	SPEED_FACTOR = speed_factor;

	GetTickCount_hook.function_name = "GetTickCount";
	GetTickCount_hook.hooked_function = (DWORD)(&my_GetTickCount);
	GetTickCount_hook.imported_module_name = "KERNEL32.dll";
	DWORD ret = IAT_hook_modules(&GetTickCount_hook);

	if (ret) print_hook_info(&GetTickCount_hook);
	else printf("Cannot hook %s\n", GetTickCount_hook.function_name);
}

void unhook_GetTickCount()
{
	if (GetTickCount_hook.table_address) {
		write_dword(GetTickCount_hook.table_address, GetTickCount_hook.original_function);
	}
}

void hook_GetTickCount64(double speed_factor)
{
	printf("HOOKING GetTickCount64\n");
	SPEED_FACTOR = speed_factor;

	GetTickCount64_hook.function_name = "GetTickCount64";
	GetTickCount64_hook.hooked_function = (DWORD)(&my_GetTickCount64);
	GetTickCount64_hook.imported_module_name = "KERNEL32.dll";
	DWORD ret = IAT_hook_modules(&GetTickCount64_hook);

	if (ret) print_hook_info(&GetTickCount64_hook);
	else printf("Cannot hook %s\n", GetTickCount64_hook.function_name);
}

void unhook_GetTickCount64()
{
	if (GetTickCount64_hook.table_address) {
		write_dword(GetTickCount64_hook.table_address, GetTickCount64_hook.original_function);
	}
}

void hook_timeGetTime(double speed_factor)
{
	printf("HOOKING timeGetTime\n");
	SPEED_FACTOR = speed_factor;

	timeGetTime_hook.function_name = "timeGetTime";
	timeGetTime_hook.hooked_function = (DWORD)(&my_timeGetTime);
	DWORD ret = IAT_hook_modules(&timeGetTime_hook);

	if (ret) print_hook_info(&timeGetTime_hook);
	else printf("Cannot hook %s\n", timeGetTime_hook.function_name);
}

void unhook_timeGetTime()
{
	if (timeGetTime_hook.table_address) {
		write_dword(timeGetTime_hook.table_address, timeGetTime_hook.original_function);
	}
}

void hook_QueryPerformanceCounter(double speed_factor)
{
	printf("HOOKING QueryPerformanceCounter\n");
	SPEED_FACTOR = speed_factor;

	// Try multiple versions of the function ...
	QueryPerfomanceCounter_hook.function_name = "RtlQueryPerformanceCounter";
	QueryPerfomanceCounter_hook.hooked_function = (DWORD)(&my_QueryPerfomanceCounter);
	DWORD ret = IAT_hook_modules(&QueryPerfomanceCounter_hook);
	if (!ret) {
		QueryPerfomanceCounter_hook.function_name = "QueryPerformanceCounter";
		ret = IAT_hook_modules(&QueryPerfomanceCounter_hook);
	}

	if (ret) {
		p_QueryPerformanceCounter func = (p_QueryPerformanceCounter)QueryPerfomanceCounter_hook.original_function;
		func(&initial_performance_counter);
		print_hook_info(&QueryPerfomanceCounter_hook);
	}
	else {
		printf("Cannot hook %s\n", QueryPerfomanceCounter_hook.function_name);
	}
}

void unhook_QueryPerformanceCounter()
{
	if (QueryPerfomanceCounter_hook.table_address) {
		write_dword(QueryPerfomanceCounter_hook.table_address, QueryPerfomanceCounter_hook.original_function);
	}
}

void WINAPI speedhack(HMODULE dll)
{
	open_console();
	printf("Hello, world!\n");
	hook_GetTickCount(SPEED_FACTOR);
	hook_GetTickCount64(SPEED_FACTOR);
	hook_timeGetTime(SPEED_FACTOR);
	hook_QueryPerformanceCounter(SPEED_FACTOR);
	/*
	std::unordered_map<std::string, DWORD> map;
	traverse_imported_symbols(map);
	print_PE_sections();
	print_modules();
	*/
}

void unhook()
{
	// NOTE: unhooking may cause the target process to 'freeze' 
	// for some time. I suspect this may be because it needs time 
	// for the real time to catch up with the sped up time? Yes, see
	// explanation in test.c.
	// Possible 'solution': don't unload the dll, instead set speed to 1?
	unhook_GetTickCount();
	unhook_GetTickCount64();
	unhook_QueryPerformanceCounter();
	unhook_timeGetTime();
	close_console();
}

// This function is called externally from speedhackAPI, to provide a 
// foreign means of access to the speedhack.
extern "C" __declspec(dllexport)
void __stdcall api_set_speed(float speed)
{
	printf("API: SET_SPEED -> %f\n", speed);
	SPEED_FACTOR = speed;
	// NOTE: if we wanted to support seamless speed transitions
	// (when decreasing speed - see test.c explanation), we would
	// have to set the initial times in the hooked time 
	// functions to the current simulated time. However, unhooking
	// would be even more problematic. Worth it? Probably...
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
	else if (ul_reason_for_call == DLL_PROCESS_DETACH && lpReserved == NULL) {
		// If the DLL is being cleanly unloaded, clean up ...
		unhook();
	}
    return TRUE;
}

