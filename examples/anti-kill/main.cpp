#include "debug.hpp"
#include "../../include/nosymonkey.hpp"

void usage(char *arg1)
{
    string sExec(arg1);
    sExec = sExec.substr(sExec.find_last_of('\\')+1);
    cout << "Prevent a process from killing another by hooking OpenProcess." << endl << endl;
    cout << "By Alex Popovici, part of NosyMonkey's examples (@alex91dotar) github.com/alex91ar" << endl;
    cout << "----------------------------------------------------------------------------------" << endl << endl;
    cout << sExec << " [target process] [unkillable process]" << endl << endl;
    cout << "Try taskmgr.exe as your target process."  << endl << endl;
    ExitProcess(1);
}
DWORD dwTargetProcess = 0;

/*
This is another cool example of how in 30 lines you can implement a ring3 anti-kill hook.
Notice that we are again referencing a global variable, so we may specify dynamically which process we'll be "protecting".


*/

uintptr_t OpenProcesHook(uintptr_t dwDesiredAccess, uintptr_t bInheritHandle, uintptr_t dwProcessId)
{
    //We may reference global variables, which will be copied and the relative offset fixed.
    if(dwProcessId == dwTargetProcess)
    {
        //SetLastError is from Kernel32.dll so it's cool to call it.
        SetLastError(5);
        return 0;
    }
    return originalCall(dwDesiredAccess, bInheritHandle, dwProcessId);
}

int main(int argc, char **argv)
{
    if(argc != 3) usage(argv[0]);
    dwTargetProcess = stoul(argv[2]);
    DWORD dwPid = getProcessId(argv[1]);
    if(dwPid)
    {
        //Kernelbase.dll is the correct dll for OpenProcess.
        //Otherwise you'll hook a jmp to Kernel32.dll, you'll be stuck in a loop and overrun your call stack.
        if(detourAPIHook(dwPid, (LPVOID)OpenProcesHook, "OpenProcess", "kernelbase.dll"))
        {
            return 0;
        }
        debugcry("detourAPIHook");
    }
    debugcry("getProcessId");
    return 1;
}
