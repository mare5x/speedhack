# Speedhack

Speedhack using IAT hooking. 

## About

A simple _speedhack_ for 32-bit Windows processes. It works by performing an **_import address table_** hook (**IAT**) on certain time related Windows functions (_GetTickCount_, _GetTickCount64_, _timeGetTime_ and _QueryPerformanceCounter_). It makes the target process think more (or less) time has passed than it really has, thus giving us a _speedhack_.
Hooking is done using **DLL injection**; a DLL injector is included in the source code.

I also explore the format of **PE headers** (sections, imports, exports ...).

## Usage

Inject _speedhack.dll_ into the target process using either _speedhackAPI.exe_ or _dll_inject.exe_.  

```
> speedhackAPI.exe <absolute path to speedhack.dll> <PID>
```   
If successful, you can now enter a number to change the speedhack speed.

### Example

Build project _tests_ and run _tests.exe_.
```
> tests.exe <0/1/2/3>  ;; 0 for GetTickCount test, 1 for GetTickCount64,   
                       ;; 2 for QueryPerformanceCounter and 3 for timeGetTime test.
```
While _tests.exe_ is running, we inject _speedhack.dll_ to start the speedhack.
To use _dll_inject.exe_ or _speedhackAPI.exe_ we need to know the process id (PID) of the target process. 
For convenience, _tests.exe_ displays its own PID when you run it.
```
> dll_inject.exe <absolute path to speedhack.dll> PID
```   
If the injection was successful, you will immediately be able to observe the effects of the speedhack on _tests.exe_.

## Build

  * _speedhack_ contains the actual speedhack (builds into speedhack.dll).
  * _speedhackAPI_ is a simple utility to inject the speedhack and control the speed (builds into speedhackAPI.exe). 
  * _dll_inject_ is a simple command line dll injector (builds into dll_inject.exe).
  * _tests_ is a simple app for testing 

  1. Open _speedhack.sln_ using Visual Studio.
  2. Build solution or individual projects (by right clicking on the solution/project in the Solution Explorer).

NOTE: be careful of process bit-ness (64-bit and 32-bit).  
NOTE: unhooking may cause the target process to 'freeze' (explanation in source).
