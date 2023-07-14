#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include <windows.h>
#include <psapi.h>
using namespace std;
#include "../src/process.hpp"

TEST_CASE("getProcessId test") {
    char szFileName[MAX_PATH];
    GetModuleFileName(NULL, szFileName, MAX_PATH);
    string processName(szFileName);
    processName = processName.substr(processName.find_last_of('\\')+1);
    // Call the function and check the result
    DWORD result = getProcessId(processName);
    REQUIRE(result == GetCurrentProcessId());
}

TEST_CASE("dupHandle test") {
    // Call the function and check the result
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
    uintptr_t currentProcess = dupHandle(GetCurrentProcessId(), GetCurrentProcess());
    char szFileName1[MAX_PATH];
    GetModuleFileNameEx(hProcess,NULL, szFileName1, MAX_PATH);
    char szFileName2[MAX_PATH];
    GetModuleFileNameEx((HANDLE)currentProcess,NULL, szFileName2, MAX_PATH);
    string s1(szFileName1);
    string s2(szFileName2);
    REQUIRE(s1 == s2);
}
