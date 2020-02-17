#include "stdio.h"
#include "sysinfoapi.h"
#include "stdbool.h"

int main(int argc, char* argv[]) 
{
    DWORD w = GetTickCount();
    while (true) {
        DWORD d = GetTickCount();
        if (d - w > 1000) {
            printf("%ull\n", d);
            w = d;
        }
    }
    return 0;
}