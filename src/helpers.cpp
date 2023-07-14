#include <string>
#include <windows.h>
#include <utility>
#include <vector>
#include <psapi.h>
#include "helpers.hpp"
using namespace std;
uint32_t copy_depth = 1;
size_t copyCodeSize = 0x400;
//DISABLED = 0
//GENERAL = 1 (DEFAULT)
//INFO = 2
//DEBUG = 3
int logLevel = 1;

uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr)
{
    uintptr_t ptrRet = 0;
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, dwPid);
    if(hProcess != NULL)
    {
        DWORD dwOldProtect;
        if(!ptr)
        {
            ptr = (uintptr_t) VirtualAllocEx(hProcess, 0, memory.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            SIZE_T stWritten = 0;
            if(WriteProcessMemory(hProcess,(LPVOID) ptr, memory.c_str(), memory.size(), &stWritten)) ptrRet = ptr;
            debugcry("WriteProcessMemory");
        }
        else
        {
            if(VirtualProtectEx(hProcess, (LPVOID)ptr, memory.size(), PAGE_EXECUTE_READWRITE, &dwOldProtect))
            {
                SIZE_T stWritten = 0;
                if(WriteProcessMemory(hProcess,(LPVOID) ptr, memory.c_str(), memory.size(), &stWritten)) ptrRet = ptr;
                debugcry("WriteProcessMemory");
                VirtualProtectEx(hProcess, (LPVOID) ptr, memory.size(), dwOldProtect, &dwOldProtect);
            }
            debugcry("VirtualProtectEx");
        }
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return ptrRet;
}

bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize)
{
    bool bRet = false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, false, dwPid);
    if(hProcess != NULL)
    {
        SIZE_T stRead = 0;
        char *szMem = new char[dwSize];
        if(ReadProcessMemory(hProcess, (LPCVOID) ptr, szMem, dwSize, &stRead))
        {
            memory.assign(szMem, stRead);
            bRet = true;
        }
        debugcry("ReadProcessMemory");
        delete [] szMem;
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return bRet;
}


bool remoteFree(DWORD dwPid, uintptr_t ptr)
{
    bool bRet = false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, false, dwPid);
    if(hProcess != NULL)
    {
        if(VirtualFreeEx(hProcess, (LPVOID)ptr, 0, MEM_RELEASE)) bRet = true;
        debugcry("VirtualFreeEx");
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return bRet;
}

void manuallyTrigger(DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, dwPid);
    if(hProcess != NULL)
    {
        string sRet(1,0xc3);
        uintptr_t remoteRet = writeToProcess(dwPid, sRet, 0);
        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE) remoteRet, 0, 0, 0);
        WaitForSingleObject(hThread, INFINITE);
        remoteFree(dwPid, remoteRet);
        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
}


bool replacestr(string& str, const string& from, const string& to)
{
    size_t start_pos = str.find(from);
    if(start_pos == string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

bool getSyscallNumber(string apiName, DWORD *sysCall)
{
    char *szApiCode = (char*) GetProcAddress(LoadLibrary("ntdll.dll"), apiName.c_str()); //Get API address.
    if(!szApiCode) return false; //API not found?
    unsigned char compare[] = "\x4c\x8b\xd1\xb8"; // mov r10, rcx; mov eax, $syscall
    if(memcmp(szApiCode, compare, sizeof(compare)-1) == 0) memcpy(sysCall, szApiCode+4, 4); //Syscall is the next 4 bytes.
    else return false; //Weird ass ntdll API? Changed signature? You go find out.
    return true;
}

bool IsAddressInTextSection(uintptr_t address)
{
    HMODULE hModule = GetModuleHandle(NULL);
    MEMORY_BASIC_INFORMATION mInfo;
    ZeroMemory(&mInfo, sizeof(mInfo));
    if (hModule == NULL)
        return false;

    MODULEINFO moduleInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)) == FALSE)
        return false;
    if(!VirtualQuery(moduleInfo.EntryPoint, &mInfo, sizeof(mInfo))) return false;
    if(mInfo.State != MEM_COMMIT) return false;
    uintptr_t startAddress = (uintptr_t) mInfo.AllocationBase;
    uintptr_t endAddress = startAddress + mInfo.RegionSize;
    return (address >= startAddress) && (address < endAddress);
}

bool isValidMemory(uintptr_t ptr)
{
    MEMORY_BASIC_INFORMATION mInfo;
    memset(&mInfo, 0, sizeof(mInfo));
    DEBUG(cout << "Target address is 0x" << (hex) << ptr << endl);
    VirtualQuery((LPCVOID)(ptr), &mInfo, sizeof(mInfo)); //Is target memory accessible?
    DEBUG(if(mInfo.State == MEM_COMMIT) cout << "Valid memory. State = 0x" << mInfo.State << endl);
    DEBUG(if(mInfo.State != MEM_COMMIT) cout << "Invalid memory. State = 0x" << mInfo.State << endl);
    if(mInfo.State == MEM_COMMIT) return true;
    else return false;
}

bool isOriginalCall(uintptr_t memoryAdd)
{
    //Horrible heuristics to see if it's originalCall
    string sOrigCall((char*)memoryAdd, 0x100);
    uintptr_t uPattern= 0xcacabebe14143322;
    string sPattern((char*)&uPattern, sizeof(uPattern));
    if(sOrigCall.find(sPattern) != string::npos) return true;
    return false;
}

void placeJumpToEntry(string &sCode, uint32_t *entryOffset)
{
    string sJmp((char*)entryOffset, sizeof(uint32_t));
    sJmp.insert(0, "\xE9");
    sCode.insert(0, sJmp);
    *entryOffset += sJmp.size();
}

void setCopyDepth(uint32_t newCopyDepth)
{
    copy_depth = newCopyDepth;
}

void setCopyCodeSize(size_t newCopyCodeSize)
{
    copyCodeSize = newCopyCodeSize;
}

void setLogLevel(int newLogLevel)
{
    logLevel = newLogLevel;
}

uint32_t handleLocalCalls(string &sCode, uintptr_t baseMemory, string sReplacecode) //Extends the code to include all local relative calls. Returns the offset of the start of the function.
{
    INFO(cout << "Handling local calls baseMemory = 0x" <<(hex) << baseMemory << " depth = " << (dec) <<  copy_depth << endl);
    INFO(cout << "Initial size 0x" << (hex) << sCode.size() << endl);
    uint32_t entryOffset = 0;
    uintptr_t memStart = baseMemory;
    uintptr_t memEnd = baseMemory + sCode.size();
    vector<uint32_t> originalCalls;
    uint32_t finalDepth = copy_depth;
    if(!sReplacecode.empty() && !finalDepth) finalDepth++; //Only force the loop if there are originalCalls.
    for(uint32_t j = 0; j < finalDepth; j++) //We need to run this loop at least once to handle original calls.
    {
        for(size_t index = 0; index < sCode.size(); index++)
        {
            if(sCode[index] == '\xE8' && index < sCode.size()) //Possible local call.
            {
                int32_t callDiff = 0;
                memcpy(&callDiff, sCode.c_str()+index+1, sizeof(int32_t));
                uintptr_t targetMemory = memStart + index + callDiff + 5; //We get the absolute target memory address.
                if(IsAddressInTextSection(targetMemory)) //Is the target memory valid and in the .text section of the current module?
                {
                    DEBUG(cout << "Found a local call in 0x" << (hex) << memStart + index << " to 0x" << (hex) << targetMemory << endl);
                    if(!isOriginalCall(targetMemory))
                    {
                        if(copy_depth) //Only expand the memory area if it's requested.
                        {
                            //We expand the copied memory area.
                            if(targetMemory > memEnd) memEnd = targetMemory + copyCodeSize;
                            if(targetMemory < memStart)
                            {
                                //If we need to reference previous memory, we need to adjust offsets and restart the loop.
                                DEBUG(cout << "Found reference to previous memory, restarting loop." << endl);
                                entryOffset += memStart - targetMemory;
                                memStart = targetMemory;
                                originalCalls.clear();
                                j--;
                                break;
                            }
                        }
                    }
                    else if(j == finalDepth-1) //Only do this for the last loop.
                    {
                        DEBUG(cout << "Found originalCall() in 0x" << (hex) << memStart + index << endl);
                        originalCalls.push_back(index+1); //We save the index
                    }
                    index+=5;
                }
                else DEBUG(cout << "Address not in .text section: 0x" << (hex) << targetMemory << endl;)
            }
        }
        sCode.assign((char*)memStart, memEnd-memStart);
        INFO(cout << "Final size = 0x" <<(hex) << sCode.size() <<  endl);
        INFO(cout << "New entry offset = 0x" << (hex) << entryOffset << endl);
    }
    string sAlign("\xCC\xCC\xCC\xCC");
    sCode.append(sAlign);
    for(size_t i = 0; i < originalCalls.size(); i++)
    {
        DWORD newOffset = sCode.size() - originalCalls[i] - sizeof(DWORD);
        INFO(cout << "originalCall() now points to offset 0x" << (hex) << originalCalls[i] + newOffset - sizeof(DWORD) << endl);
        string sNewOffset((char*)&newOffset, sizeof(DWORD));
        sCode.replace(originalCalls[i], sNewOffset.size(), sNewOffset);
    }
    sCode.append(sReplacecode);
    return entryOffset;
}
