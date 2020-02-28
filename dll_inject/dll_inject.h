#include "windows.h"

HMODULE load_dll(HANDLE proc, const char* dll_path);

int unload_dll_by_handle(HANDLE proc, HMODULE dll_handle);
int unload_dll_by_name(HANDLE proc, const char* dll);
