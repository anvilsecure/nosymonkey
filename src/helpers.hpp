#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
using namespace std;

#ifndef __clang__
#error "You should compile this with Clang. Other compilers have not been tried"
#endif // __clang__
#ifndef _WIN64
#error "This is for Windows 64 bits! If you try to compile it for linux you're gonna fall into a deep rabbit hole..."
#endif // __clang__

uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr);
bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize);
bool replacestr(string& str, const string& from, const string& to);
bool getSyscallNumber(string apiName, DWORD *sysCall);
bool remoteFree(DWORD dwPid, uintptr_t ptr);
void manuallyTrigger(DWORD dwPid);
uint32_t handleLocalCalls(string &sCode, uintptr_t baseMemory, string sReplacecode = "");
bool isValidMemory(uintptr_t ptr);
void placeJumpToEntry(string &sCode, uint32_t *entryOffset);
extern int logLevel;
bool isOriginalCall(uintptr_t memoryAdd);
bool IsAddressInTextSection(uintptr_t address);
#define GENERAL(s) if(logLevel >= 1) s
#define INFO(s) if(logLevel >=2) s
#define DEBUG(s) if(logLevel >=3) s
#define debugcry(s) else if(logLevel >=3) cout << "Error in " << s << " GLE: " << (dec) << GetLastError() << endl;
