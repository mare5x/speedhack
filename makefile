all : test dll inject

test : test.o
	gcc -o test test.o 

test.o : test.c
	gcc -c test.c

dll : speedhack.o
	gcc -shared -o speedhack.dll speedhack.o win_console.o

speedhack.o : speedhack.c win_console.c
	gcc -c speedhack.c win_console.c 

inject : inject.o
	gcc -o inject dll_inject.o

inject.o : dll_inject.c 
	gcc -c dll_inject.c 

clean :
	rm test inject speedhack *.o