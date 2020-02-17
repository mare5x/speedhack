#include "windows.h"
#include "win_console.h"
#include <stdio.h>

void WINAPI speedhack(HMODULE dll)
{
    open_console();
    printf("Hello, world!\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) 
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HANDLE thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&speedhack, hModule, NULL, NULL);
        CloseHandle(thread);        
    }
    return TRUE;
}