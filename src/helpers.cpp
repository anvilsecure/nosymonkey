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

bool isValidMemory(uintptr_t ptr)
{
    MEMORY_BASIC_INFORMATION mInfo;
    memset(&mInfo, 0, sizeof(mInfo));
    cout << "Target address is 0x" << (hex) << ptr << endl;
    #ifdef VERBOSE
    cout << "Target address is 0x" << (hex) << ptr << endl;
    #endif // VERBOSE
    VirtualQuery((LPCVOID)(ptr), &mInfo, sizeof(mInfo)); //Is target memory accessible?
    #ifdef VERBOSE
    if(mInfo.State == MEM_COMMIT) cout << "Valid memory. State = 0x" << mInfo.State << endl;
    else cout << "Invalid memory. State = 0x" << mInfo.State << endl;
    #endif // VERBOSE
    if(mInfo.State == MEM_COMMIT) return true;
    else return false;
}

bool isOriginalFunction(uintptr_t targetMemory)
{
    //Not Implemented.
    /*string sOrig("\xCC\xCC\xCC\xCC\xCC"); //Probably not the best idea, but the best I can think of right now.
    string sTarg((char*)targetMemory, 0x8);
    if(sOrig.compare(sTarg) == 0) return true;
    else return false;*/
    return true;
}

void replaceCallIfValid(string &sCode, uintptr_t baseMemory, string originalFunc)
{
    size_t originalSize = sCode.size();
    for(size_t index = 0; index < originalSize; index++)
    {
        if(sCode[index] == '\xE8' && index < originalSize - 5)
        {
            int32_t callDiff = 0;
            memcpy(&callDiff, sCode.c_str()+index+1, sizeof(int32_t));
            uintptr_t targetMemory = baseMemory + index + callDiff -5;
            if(isValidMemory(targetMemory))
            {
                if(isOriginalFunction(targetMemory))
                {
                    sCode.append("\xCC\xCC\xCC\xCC"); //Alignment
                    int32_t newDiff = sCode.size() - index -5;
                    string sDiff((char*)&newDiff, sizeof(int32_t));
                    sCode.replace(index+1, 4, sDiff);
                    sCode.append(originalFunc);
                }
                else
                {
                    //Not implemented.
                }
            }
        }
    }
}
