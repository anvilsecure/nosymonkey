#include <iostream>
#include <string>
#include <windows.h>
#include "debug.hpp"
#define HEURISTIC_TOLERANCE 0x10000
using namespace std;

uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr)
{
    uintptr_t ptrRet = 0;
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, dwPid);
    if(hProcess != NULL)
    {
        DWORD dwOldProtect;
        if(!ptr)
        {
            ptr = (uintptr_t) VirtualAllocEx(hProcess, 0, memory.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            SIZE_T stWritten = 0;
            if(WriteProcessMemory(hProcess,(LPVOID) ptr, memory.c_str(), memory.size(), &stWritten)) ptrRet = ptr;
            debugcry("WriteProcessMemory");
        }
        else
        {
            if(VirtualProtectEx(hProcess, (LPVOID)ptr, memory.size(), PAGE_EXECUTE_READWRITE, &dwOldProtect))
            {
                SIZE_T stWritten = 0;
                if(WriteProcessMemory(hProcess,(LPVOID) ptr, memory.c_str(), memory.size(), &stWritten)) ptrRet = ptr;
                debugcry("WriteProcessMemory");
                VirtualProtectEx(hProcess, (LPVOID) ptr, memory.size(), dwOldProtect, &dwOldProtect);
            }
            debugcry("VirtualProtectEx");
        }
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return ptrRet;
}

bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize)
{
    bool bRet = false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, false, dwPid);
    if(hProcess != NULL)
    {
        SIZE_T stRead = 0;
        char *szMem = new char[dwSize];
        if(ReadProcessMemory(hProcess, (LPCVOID) ptr, szMem, dwSize, &stRead))
        {
            memory.assign(szMem, stRead);
            bRet = true;
        }
        debugcry("ReadProcessMemory");
        delete [] szMem;
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return bRet;
}


bool remoteFree(DWORD dwPid, uintptr_t ptr)
{
    bool bRet = false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, false, dwPid);
    if(hProcess != NULL)
    {
        if(VirtualFreeEx(hProcess, (LPVOID)ptr, 0, MEM_RELEASE)) bRet = true;
        debugcry("VirtualFreeEx");
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return bRet;
}

void manuallyTrigger(DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, dwPid);
    if(hProcess != NULL)
    {
        string sRet(1,0xc3);
        uintptr_t remoteRet = writeToProcess(dwPid, sRet, 0);
        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE) remoteRet, 0, 0, 0);
        WaitForSingleObject(hThread, INFINITE);
        remoteFree(dwPid, remoteRet);
        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
}


bool replacestr(string& str, const string& from, const string& to)
{
    size_t start_pos = str.find(from);
    if(start_pos == string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

bool getSyscallNumber(string apiName, DWORD *sysCall)
{
    char *szApiCode = (char*) GetProcAddress(LoadLibrary("ntdll.dll"), apiName.c_str()); //Get API address.
    if(!szApiCode) return false; //API not found?
    unsigned char compare[] = "\x4c\x8b\xd1\xb8"; // mov r10, rcx; mov eax, $syscall
    if(memcmp(szApiCode, compare, sizeof(compare)-1) == 0) memcpy(sysCall, szApiCode+4, 4); //Syscall is the next 4 bytes.
    else return false; //Weird ass ntdll API? Changed signature? You go find out.
    return true;
}

void replaceCallIfValid(string &sCode, size_t index)
{
    if(sCode[index] == '\xE8' && index < sCode.size() - 5)
    {
        int32_t callDiff = 0;
        memcpy(&callDiff, sCode.c_str()+index+1, sizeof(int32_t));
        cout << "Calldiff = 0x" << (hex) << callDiff << endl;
        if(abs(callDiff) < HEURISTIC_TOLERANCE)
        {
            int32_t newDiff = sCode.size() - index -5;
            string sDiff((char*)&newDiff, sizeof(int32_t));
            sCode.replace(index+1, 4, sDiff);
        }
    }
}
