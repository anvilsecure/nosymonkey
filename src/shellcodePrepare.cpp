#include "debug.hpp"
#include "helpers.hpp"
#define STRINGS_START 0x800
#include <vector>


void replaceIATCalls(string &shellCode, uintptr_t memStart)
{
    string leaRax("\x48\x8d\x05");
    string leaRbx("\x48\x8d\x1d");
    string leaRcx("\x48\x8d\x0d");
    string leaRdx("\x48\x8d\x15");
    string leaR8("\x4c\x8d\x05");
    string leaR9("\x4c\x8d\x0d");
    string movEAXDWORD("\x8B\x05");
    string movEBXDWORD("\x8B\x1D");
    string movECXDWORD("\x8B\x0D");
    string movEDXDWORD("\x8B\x15");
    string movR8DDWORD("\x44\x8B\x05");
    string movR9DDWORD("\x44\x8B\x0D");
    string movEDIDWORD("\x8B\x3D");
    //string movRAXQWORD("\x48\xA1");
    string movRBXQWORD("\x48\x8b\x1d");
    string movRCXQWORD("\x48\x8b\x0d");
    string movRDXQWORD("\x48\x8b\x15");
    string movR8QWORD("\x48\x8b\x05");
    string movR9QWORD("\x48\x8b\x0D");
    string movRDIQWORD("\x48\x8b\x3d");
    string movR14QWORD("\x4C\x8b\x35");
    string callSignature("\xFF\x15");
    vector<string> vCompares = {leaRax, leaRcx, leaRbx, leaRdx, leaR8, leaR9,movEAXDWORD,
    movEBXDWORD,movECXDWORD,movEDXDWORD,movR8DDWORD,movR9DDWORD,movEDIDWORD,
    //movRAXQWORD,
    movRBXQWORD,movRCXQWORD,movRDXQWORD,movR8QWORD,movR9QWORD, movRDIQWORD, movR14QWORD, callSignature};
    for(long i = 0; i < shellCode.size(); i++)
    {
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
                #ifdef VERBOSE
                cout << "Offset is 0x" << (hex) << (dwOffset - (it.size()+4)) << endl;
                #endif // VERBOSE
                if(isValidMemory(memStart + dwOffset + i))
                {
                    char *pszData = (char*) (memStart + dwOffset + i);
                    #ifdef VERBOSE
                    cout << "Accessible memory. String = " << pszData << endl;
                    #endif // VERBOSE
                    size_t dataLen = strlen(pszData)+1;
                    DWORD dwNewOffset = shellCode.size() - i - sizeof(DWORD) - it.size();
                    if(dataLen < sizeof(uintptr_t)) dataLen = sizeof(uintptr_t);
                    string sData(pszData, dataLen);
                    string sNewOffset((char*)&dwNewOffset, sizeof(DWORD));
                    shellCode.append(sData);
                    shellCode.replace(i+it.size(), sNewOffset.size(), sNewOffset);
                    i+=3+it.size();
                    break;
                }
            }
        }
    }
}
