#include "debug.hpp"
#include "helpers.hpp"

void replaceIATCalls(string &shellCode, uintptr_t memStart)
{
    string callSignature("\xFF\x15");
    for(long i = 0; i < shellCode.size(); i++)
    {
        if(shellCode.substr(i, 2).compare(callSignature) == 0 && i + 6 < shellCode.size())
        {
            #ifdef VERBOSE
            cout << "Found CALL QWORD PTR at 0x" << (hex) << (memStart+i) << endl;
            #endif // VERBOSE
            DWORD dwOffset = 0;
            memcpy(&dwOffset, shellCode.substr(i+2, 4).c_str(), sizeof(DWORD)); //Get offset for IAT pointer.
            dwOffset +=6;
            MEMORY_BASIC_INFORMATION mInfo;
            memset(&mInfo, 0, sizeof(mInfo));
            #ifdef VERBOSE
            cout << "Offset is 0x" << (hex) << (dwOffset + -6) << endl;
            cout << "IAT address is 0x" << (hex) << (memStart + dwOffset + i) << endl;
            #endif // VERBOSE
            VirtualQuery((LPCVOID)(memStart + dwOffset + i), &mInfo, sizeof(mInfo)); //Is target memory accessible?
            #ifdef VERBOSE
            cout << "Memory state is " << (hex) << mInfo.State << endl;
            cout << "Memory protection is " << (hex) << mInfo.Protect << endl;
            #endif // VERBOSE
            if(mInfo.State == MEM_COMMIT)
            {
                uintptr_t APIcall = *((uintptr_t*)(memStart+dwOffset + i)); //Get address from IAT.
                #ifdef VERBOSE
                cout << "Accessible memory. API Address = 0x" << (hex) << APIcall << endl;
                #endif // VERBOSE
                memset(&mInfo, 0, sizeof(mInfo));
                VirtualQuery((LPCVOID)(APIcall), &mInfo, sizeof(mInfo)); //Is it a valid address?
                if(mInfo.State == MEM_COMMIT)
                {
                    #ifdef VERBOSE
                    cout << "Accessible memory. Modifying with absolute call." << endl;
                    #endif // VERBOSE
                    char szAbsCall[] = "\x48\xB8\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xFF\xD0";
                    memcpy(szAbsCall+2, &APIcall, sizeof(APIcall));
                    string sAbsCall(szAbsCall, sizeof(szAbsCall)-1);
                    replacestr(shellCode, shellCode.substr(i,6), sAbsCall);
                    i+=sizeof(szAbsCall);
                }
            }
        }
    }
}
