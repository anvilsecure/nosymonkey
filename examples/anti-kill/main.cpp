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

uintptr_t OpenProcesHook(uintptr_t dwDesiredAccess, uintptr_t bInheritHandle, uintptr_t dwProcessId)
{
    if(dwProcessId == dwTargetProcess)
    {
        SetLastError(5);
        return originalCall(1, 2, 3);
    }
    return originalCall(dwDesiredAccess, bInheritHandle, dwProcessId);
}

int main(int argc, char **argv)
{
    if(argc != 3) usage(argv[0]);
    dwTargetProcess = stoul(argv[2]);
    if(givePrivs(GetCurrentProcessId()))
    {
        DWORD dwPid = getProcessId(argv[1]);
        if(dwPid)
        {
            if(detourAPIHook(dwPid, (LPVOID)OpenProcesHook, "OpenProcess", "kernelbase.dll"))
            {
                Sleep(-1);
                return 0;
            }
            debugcry("detourAPIHook");
        }
        debugcry("getProcessId");
    }
    debugcry("givePrivs");
    return 1;
}
