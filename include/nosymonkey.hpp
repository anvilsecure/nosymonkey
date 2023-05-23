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
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
    asm("int $3");
}
bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName);
bool detourAPIHook(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName, string dllName);
uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr);
bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize);
bool replacestr(string& str, const string& from, const string& to);
bool getSyscallNumber(string apiName, DWORD *sysCall);
bool remoteFree(DWORD dwPid, uintptr_t ptr);
void manuallyTrigger(DWORD dwPid);
DWORD getProcessId(string processName);
bool givePrivs(DWORD dwPid);
uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t* dwGLE, vector<uintptr_t> args);
uintptr_t dupHandle(DWORD dwPid, HANDLE hHandle);
uintptr_t copyAndExecWithParams(DWORD dwPid, LPCVOID localFunc, uintptr_t* dwGLE, vector<uintptr_t> args);
#endif // __ORIGINAL_CALL__

