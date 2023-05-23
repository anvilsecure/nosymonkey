#include <iostream>
#include <string>
#include <windows.h>
using namespace std;

uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr);
bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize);
bool replacestr(string& str, const string& from, const string& to);
bool getSyscallNumber(string apiName, DWORD *sysCall);
bool remoteFree(DWORD dwPid, uintptr_t ptr);
void manuallyTrigger(DWORD dwPid);
void replaceCallIfValid(string &sCode, uintptr_t baseMemory, string originalFunc);
bool isValidMemory(uintptr_t ptr);
