#include "windows.h"
#include "stdio.h"
#include "stdbool.h"
#include "stdlib.h"

int main(int argc, char* argv[]) 
{
	printf("PID: %lu\n", GetCurrentProcessId());
    DWORD w = GetTickCount();
	srand(w);
    while (true) {
        DWORD d = GetTickCount();
        if (d - w > 1000) {
            printf("%lu\n", d);
            w = d;
        }
		Sleep(rand() % 100);
    }
    return 0;
}
