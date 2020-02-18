// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <cstdio>

void WINAPI speedhack(HMODULE dll)
{
	printf("Hello, world!\n");
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

