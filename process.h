#pragma once

#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>

#include <Windows.h>
#include <TlHelp32.h>

struct Process
{
  public:
    static constexpr DWORD FULL_ACCESS =
        PROCESS_ALL_ACCESS | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

    Process(DWORD pid, DWORD desiredAccess = FULL_ACCESS, BOOL inheritHandle = FALSE)
    {
        handle = OpenProcess(desiredAccess, inheritHandle, pid);
        if (!handle)
        {
            std::stringstream stream;
            stream << "OpenProcess failed, GetLastError: " << GetLastError();
            throw std::runtime_error(stream.str());
        }
    }

    Process(const char *name, DWORD desiredAccess = FULL_ACCESS, BOOL inheritHandle = FALSE)
        : Process(GetProcId(name), desiredAccess, inheritHandle)
    {
    }

    virtual ~Process()
    {
        if (handle)
        {
            CloseHandle(handle);
        }
    }

    template <typename T> T ReadMem(DWORD64 addr)
    {
        T buf(0);
        ReadProcessMemory(handle, (LPCVOID)addr, &buf, sizeof(T), NULL);
        return buf;
    }

    template <typename T> bool VerifyMem(DWORD64 addr, T value)
    {
        return ReadMem<T>(addr) == value;
    }

    template <typename T> void PatchMem(DWORD64 addr, T value, bool verify = true)
    {
        DWORD oldprotect;
        VirtualProtectEx(handle, (LPVOID)addr, sizeof(T), PAGE_EXECUTE_READWRITE, &oldprotect);
        WriteProcessMemory(handle, (LPVOID)addr, (LPCVOID)&value, sizeof(T), NULL);
        VirtualProtectEx(handle, (LPVOID)addr, sizeof(T), oldprotect, &oldprotect);

        if (verify && !VerifyMem(addr, value))
        {
            std::stringstream stream;
            stream << "Failed to patch value 0x" << std::hex << (DWORD64)value << " at address 0x" << addr << std::dec;
            throw std::runtime_error(stream.str());
        }
    }

    MEMORY_BASIC_INFORMATION QueryMem(DWORD64 addr)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T virt = VirtualQueryEx(handle, (LPCVOID)addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        return mbi;
    }

    DWORD GetProcId(const char *name)
    {
        int pid = 0;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshot)
        {
            return 0;
        }

        PROCESSENTRY32 pe{sizeof(PROCESSENTRY32)};
        BOOL hResult = Process32First(hSnapshot, &pe);

        while (hResult)
        {
            if (strcmp(name, pe.szExeFile) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
            hResult = Process32Next(hSnapshot, &pe);
        }

        CloseHandle(hSnapshot);
        return pid;
    }

  private:
    HANDLE handle;
};
