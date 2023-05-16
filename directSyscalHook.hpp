#include <iostream>
#include <string>
#include <windows.h>
using namespace std;

#ifndef __ORIGINAL_CALL__
#define __ORIGINAL_CALL__
template<typename... Args>  NTSTATUS __attribute__((aligned (8)))originalCall(Args... args) //Dummy function to replace in code.
{
    asm("int 3");
    return 0;
}
#endif // __ORIGINAL_CALL__
bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName);
