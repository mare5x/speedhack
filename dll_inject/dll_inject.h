#include "windows.h"

HMODULE load_dll(HANDLE proc, const char* dll_path);

void unload_dll(HANDLE proc, HMODULE dll_handle);
