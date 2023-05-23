#include "debug.hpp"
#include "helpers.hpp"
#include "shellcodePrepare.hpp"
extern uintptr_t g_nosyFunction;

__attribute__((naked)) void directSysCall()
{
    asm("push rbp");
    asm("mov rbp, rsp");
    asm("push [rbp+0x60]"); //Original param 12
    asm("push [rbp+0x58]"); //Original param 11
    asm("push [rbp+0x50]"); //Original param 10
    asm("push [rbp+0x48]"); //Original param 9
    asm("push [rbp+0x40]");//Original param 8
    asm("push [rbp+0x38]"); //Original param 7
    asm("push [rbp+0x30]"); //Original param 6
    asm("push [rbp+0x28]"); //Original param 5
    asm("push [rbp+0x20]"); //Original param 5
    asm("push [rbp+0x18]"); //Original param 5
    asm("push [rbp+0x10]"); //Original param 5
    asm("push [rbp+0x8]"); //Original param 5
    asm("push [rbp]"); //Original param 5
    asm("mov r10,rcx");
    asm("mov eax, 0x48484848"); //This is "HHHH".
    asm("syscall");
    asm("mov rsp, rbp");
    asm("pop rbp");
    asm("ret");
    asm("push rax"); //These are opcodes "PPPP", to find the end of the function easily. IDDQD
    asm("push rax");
    asm("push rax");
    asm("push rax");
}

void replaceInFunction(string &sFunc, DWORD dwSyscall)
{
    string sReplacement((char*) directSysCall, 0x400); //Who said C is not beautiful? Initialize an std::string with a char pointer static casted from a function pointer. IDDQD.
    sReplacement = sReplacement.substr(0, sReplacement.find("PPPP")); //Here we have the direct syscall function.
    string sSysCall((char*)(&dwSyscall), sizeof(dwSyscall)); //Another IDDQD moment.
    replacestr(sReplacement, "HHHH", sSysCall); //Replace the syscall number with the correct one.
    sFunc.append("\xCC\xCC\xCC\xCC"); //Alignment
    for(size_t i = 0; i < sFunc.size();i++)
    {
        replaceCallIfValid(sFunc, i);
    }
    sFunc.append(sReplacement);
}

bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName)
{
    string sFunc((char*)lpShellCodeFunc, 0x1000);
    DWORD dwSysCall = 0;
    if(getSyscallNumber(apiName, &dwSysCall))
    {
        replaceIATCalls(sFunc, (uintptr_t)lpShellCodeFunc);
        replaceInFunction(sFunc, dwSysCall);
        uintptr_t targetApi = (uintptr_t) GetProcAddress(LoadLibrary("ntdll.dll"), apiName.c_str()); //Get API address.
        uintptr_t targetHook = writeToProcess(dwPid, sFunc, 0);
        if(targetHook)
        {
            unsigned char szHook[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xC3, 0xC3, 0xC3};
            memcpy(szHook+2, &targetHook, sizeof(uintptr_t));
            string sHook((char*)szHook, sizeof(szHook)-1);
            if(writeToProcess(dwPid, sHook, targetApi)) return true;
            debugcry("writeToProcess");
        }
        debugcry("writeToProcess");
    }
    debugcry("getSyscallNumber");
    return false;
}
