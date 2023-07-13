#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#ifdef VERBOSE
#define debugcry(s) else cout << "Error in " << s << " GLE: " << (dec) << GetLastError() << endl;
#else
#define debugcry(s)
#endif // VERBOSE
using namespace std;
#ifndef __ORIGINAL_CALL__
#define __ORIGINAL_CALL__
//This function will never be called, but I need to prevent a call to it from being optimized.
#pragma clang optimize off //Sorry, optimization will break the calling convention.
template<typename... Args> uintptr_t __attribute__((noinline)) originalCall(Args... args) //Dummy function to replace in code.
{
    uintptr_t result = (uintptr_t) VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    result +=0xcacabebe14143322;
    VirtualFree((LPVOID)result, 0x1000, MEM_RELEASE);
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    return result;
}
bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName);
bool detourAPIHook(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName, string dllName);
uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr);
bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize);
bool remoteFree(DWORD dwPid, uintptr_t ptr);
DWORD getProcessId(string processName);
bool givePrivs(DWORD dwPid);
uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t* dwGLE, vector<uintptr_t> args);
uintptr_t dupHandle(DWORD dwPid, HANDLE hHandle);
uintptr_t copyAndExecWithParams(DWORD dwPid, LPCVOID localFunc, uintptr_t* dwGLE, vector<uintptr_t> args);
void setCopyDepth(uint32_t newCopyDepth);
void setCopyCodeSize(size_t newCopyCodeSize);
void setLogLevel(int newLogLevel);
#endif // __ORIGINAL_CALL__

