# win32-process-wrapper

A C++ header-only library that wraps some of the Win32 memoryapi.h functions for accessing and modifying a process's virtual memory.

## How to use

```cpp
Process myProc{"myProc.exe"};
DWORD someValue = myProc.ReadMem(0x12345678);
myProc.PatchMem(0x12345678, value + 1);
```