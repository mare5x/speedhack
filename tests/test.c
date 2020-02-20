#include "windows.h"
#include "stdio.h"
#include "stdbool.h"
#include "stdlib.h"

void tick_count_test()
{
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
}

void query_performance_counter_test()
{
	LARGE_INTEGER s, t, f;
	QueryPerformanceFrequency(&f);
	QueryPerformanceCounter(&s);
	srand(s.QuadPart);
    while (true) {
		QueryPerformanceCounter(&t);
        if ((t.QuadPart - s.QuadPart) * 1000000 / f.QuadPart > 1000000) {
            printf("%llu\n", t.QuadPart);
            s = t;
        }
		Sleep(rand() % 100);
    }
}

int main(int argc, char* argv[]) 
{
	printf("PID: %lu\n", GetCurrentProcessId());
	
	switch (argv[1][0]) {
	case '0': tick_count_test(); break;
	case '1': query_performance_counter_test(); break;
	}

    return 0;
}
