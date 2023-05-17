#include "debug.hpp"
#include "helpers.hpp"
#define STRINGS_START 0x800
#include <vector>

bool relativeToAbsolute(string &sOutput, char *pszData, string opcode)
{
    sOutput.append(opcode);
    string sData;
    if(opcode.size() == 2) //Extra check in case of a CALL PTR
    {
        MEMORY_BASIC_INFORMATION mInfo;
        memset(&mInfo, 0, sizeof(mInfo));
        uintptr_t APIcall = *((uintptr_t*)(pszData)); //Get address from IAT.
        VirtualQuery((LPCVOID)(APIcall), &mInfo, sizeof(mInfo)); //Is it a valid address?
        if(mInfo.State != MEM_COMMIT) return false;
        #ifdef VERBOSE
        cout << "Accessible memory. API Address = 0x" << (hex) << APIcall << endl;
        #endif // VERBOSE
        sData.assign((char*)&APIcall, sizeof(uintptr_t));
    }
    else
    {
        #ifdef VERBOSE
        cout << "Accessible memory. String = " << pszData << endl;
        #endif // VERBOSE
        sData.assign(pszData, strlen(pszData)+1);
    }
    DWORD dwNewOffset = 5; // Size of indirect 4 byte jmp.
    sOutput.append((char*)&dwNewOffset, sizeof(DWORD));
    DWORD dwJmpSize = sData.size();
    sOutput.append("\xE9"); //4 byte jmp.
    sOutput.append((char*)&dwJmpSize, sizeof(DWORD)); //Skip data.
    sOutput.append(sData); //append data.
    return true;
}

void replaceIATCalls(string &shellCode, uintptr_t memStart)
{
    string leaRax("\x48\x8d\x05");
    string leaRcx("\x48\x8d\x0d");
    string leaRdx("\x48\x8d\x15");
    string leaR8("\x4c\x8d\x05");
    string leaR9("\x4c\x8d\x0d");
    string callSignature("\xFF\x15");
    vector<string> vCompares = {leaRax, leaRcx, leaRdx, leaR8, leaR9, callSignature};
    string sOut;
    for(long i = 0; i < shellCode.size(); i++)
    {
        bool bFound = false;
        for (auto& it : vCompares)
        {
            if(shellCode.substr(i, it.size()).compare(it) == 0 && i + (it.size()+4) < shellCode.size())
            {
                #ifdef VERBOSE
                cout << "Found CALL or LEA QWORD PTR at 0x" << (hex) << (memStart+i) << endl;
                #endif // VERBOSE
                DWORD dwOffset = 0;
                memcpy(&dwOffset, shellCode.substr(i+it.size(), 4).c_str(), sizeof(DWORD)); //Get offset for IAT pointer.
                dwOffset +=it.size()+4;
                MEMORY_BASIC_INFORMATION mInfo;
                memset(&mInfo, 0, sizeof(mInfo));
                #ifdef VERBOSE
                cout << "Offset is 0x" << (hex) << (dwOffset - (it.size()+4)) << endl;
                cout << "Target address is 0x" << (hex) << (memStart + dwOffset + i) << endl;
                #endif // VERBOSE
                VirtualQuery((LPCVOID)(memStart + dwOffset + i), &mInfo, sizeof(mInfo)); //Is target memory accessible?
                #ifdef VERBOSE
                cout << "Memory state is " << (hex) << mInfo.State << endl;
                cout << "Memory protection is " << (hex) << mInfo.Protect << endl;
                #endif // VERBOSE
                if(mInfo.State == MEM_COMMIT)
                {
                    string sAbsolute;
                    if(relativeToAbsolute(sAbsolute, (char*)(memStart+dwOffset + i), it))
                    {
                        sOut.append(sAbsolute);
                        i+=3+it.size();
                        bFound = true;
                        break;
                    }
                }
            }
        }
        if(!bFound) sOut.append(shellCode.substr(i, 1));
    }
    shellCode = sOut;
}
