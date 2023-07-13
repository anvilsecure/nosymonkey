#include "helpers.hpp"
#include "remoteExecute.hpp"
#include "shellcodePrepare.hpp"

bool copyToMe(string sDll, string &sDest, bool bCopy)
{
    if(!bCopy)
    {
        sDest = sDll;
        return 1;
    }
    char szSource[MAX_PATH];
    char szSelfName[MAX_PATH];
    if(!GetModuleFileName(GetModuleHandle(sDll.c_str()), szSource, MAX_PATH)) return false; //Get path of target DLL to copy.
    if(!GetModuleFileName(NULL, szSelfName, MAX_PATH)) return false; //Get full path to self.
    string sSource(szSource);
    string sSelf(szSelfName);
    sDest = sSelf.substr(0, sSelf.find_last_of('\\')+1); //Strip filename from path.
    sDest += "new";
    sDest += sSource.substr(sSource.find_last_of('\\')+1); //Same filename as source.
    return CopyFile(sSource.c_str(), sDest.c_str(), false);
}

uintptr_t dllShadowLoad(DWORD dwPid, string sDll, bool bCopy=true)
{
    string shadowLoadTarget;
    if(copyToMe(sDll, shadowLoadTarget,bCopy))
    {
        INFO(cout << "Shadow Load Target = " << shadowLoadTarget << endl);
        uintptr_t dllParam = allocateParam(dwPid, shadowLoadTarget);
        uintptr_t loadLib = (uintptr_t) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        uintptr_t remoteGLE = 0;
        uintptr_t toRet = execWithParams(dwPid, loadLib,&remoteGLE, {dllParam});
        freeParam(dwPid, dllParam);
        return toRet;
    }
    debugcry("copyToMe");
    return 0;
}
