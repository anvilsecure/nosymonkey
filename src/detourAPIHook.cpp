#include "debug.hpp"
#include "helpers.hpp"
#include "dllShadowLoad.hpp"
#include "shellcodePrepare.hpp"
#include <utility>
#include <map>
using namespace std;

map<pair<DWORD, string>,uintptr_t> shadowLoadedAdds;

__attribute__((naked)) void callOriginalDetour()
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
    asm("push [rbp+0x20]"); //Shadow Space
    asm("push [rbp+0x18]"); //Shadow Space
    asm("push [rbp+0x10]"); //Shadow Space
    asm("push [rbp+0x8]"); //Shadow Space
    asm("mov rax, 0x4848484848484848"); //This is "HHHHHHHH".
    asm("call rax");
    asm("mov rsp, rbp");
    asm("pop rbp");
    asm("ret");
    asm("push rax"); //These are opcodes "PPPP", to find the end of the function easily. IDDQD
    asm("push rax");
    asm("push rax");
    asm("push rax");
}

void replaceInFunctionDetour(string &sFunc, uintptr_t originalAPI, uintptr_t baseMemory)
{
    string sReplacement((char*) callOriginalDetour, 0x400); //Who said C is not beautiful? Initialize an std::string with a char pointer static casted from a function pointer. IDDQD.
    sReplacement = sReplacement.substr(0, sReplacement.find("PPPP")); //Here we have the call to the original function.
    string sOriginalAPI((char*)(&originalAPI), sizeof(originalAPI)); //Another IDDQD moment.
    replacestr(sReplacement, "HHHHHHHH", sOriginalAPI); //Replace the call to the new shadowLoaded Dll resolved function address.
    replaceCallIfValid(sFunc, baseMemory, sReplacement);
}

uintptr_t getShadowProcAddress(DWORD dwPid, string dllName, uintptr_t targetApi)
{
    uintptr_t baseAdd = 0;
    if(shadowLoadedAdds.find(make_pair(dwPid, dllName)) != shadowLoadedAdds.end()) baseAdd = shadowLoadedAdds[make_pair(dwPid, dllName)]; //Check if reference to shadow loaded dll for a PID is present.
    else
    {
        baseAdd = dllShadowLoad(dwPid, dllName); //We shadow load our desired dll.
        if(baseAdd)
        {
            shadowLoadedAdds[make_pair(dwPid, dllName)] = baseAdd; //We save the base pointer.
        }
        else return 0;
    }
    return (targetApi - (uintptr_t) GetModuleHandle(dllName.c_str())) + baseAdd; //We return the new shadow loaded API by using the relative address.
}

bool detourAPIHook(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName, string dllName)
{
    string sFunc((char*)lpShellCodeFunc, 0x1000);
    uintptr_t targetApi = (uintptr_t) GetProcAddress(LoadLibrary(dllName.c_str()), apiName.c_str()); //Get API address.
    if(targetApi)
    {
        uintptr_t targetShadowAPI = getShadowProcAddress(dwPid, dllName, targetApi);
        if(targetShadowAPI)
        {
            replaceIATCalls(sFunc, (uintptr_t)lpShellCodeFunc);
            replaceInFunctionDetour(sFunc, targetShadowAPI, (uintptr_t)lpShellCodeFunc);
            uintptr_t targetHook = writeToProcess(dwPid, sFunc, 0);
            if(targetHook)
            {
                #ifdef VERBOSE
                cout << "Hooking " << apiName << " from " << dllName << "(0x" << (hex) << targetApi << ")." << endl;
                cout << "Replacing function in 0x" << (hex) << targetHook << endl;
                #endif // DEBUG
                unsigned char szHook[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xC3, 0xC3, 0xC3};
                memcpy(szHook+2, &targetHook, sizeof(uintptr_t));
                string sHook((char*)szHook, sizeof(szHook)-1);
                if(writeToProcess(dwPid, sHook, targetApi)) return true;
                debugcry("writeToProcess");
            }
            debugcry("writeToProcess");
        }
        debugcry("getShadowProcAddress");
    }
    debugcry("GetProcAddress");
    return false;
}

