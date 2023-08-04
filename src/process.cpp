#include "helpers.hpp"
#include <psapi.h>
#include <tlhelp32.h>

DWORD getProcessId(string processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot != INVALID_HANDLE_VALUE)
    {
        Process32First(processesSnapshot, &processInfo);
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
        while (Process32Next(processesSnapshot, &processInfo))
        {
            if (!processName.compare(processInfo.szExeFile))
            {
                CloseHandle(processesSnapshot);
                return processInfo.th32ProcessID;
            }
        }
        CloseHandle(processesSnapshot);
    }
    debugcry("CreateToolhelp32Snapshot");
    return 0;
}

uintptr_t dupHandle(DWORD dwPid, HANDLE hHandle)
{
    uintptr_t out = INVALID_HANDLE_VALUE;
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, dwPid);
    if(hProcess)
    {
        HANDLE hOut;
        if(DuplicateHandle(GetCurrentProcess(),hHandle, hProcess, &hOut, NULL, false, DUPLICATE_SAME_ACCESS))
        {
            out = (uintptr_t) hOut;
        }
        debugcry("DuplicateHandle");
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return out;
}
