#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "../src/helpers.hpp"
#include "../include/nosymonkey.hpp"
using namespace std;
// Include the header file where the functions are defined

const char globalVariable[] = "Test";

// Define the unit tests using the TEST_CASE macro
TEST_CASE("writeToProcess test") {
    char szMemtest[] = "Test Memory";
    const char szBinaryData[] = "\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00";
    string memory(szBinaryData,sizeof(szBinaryData));
    DWORD dwPid = GetCurrentProcessId();
    uintptr_t ptr = (uintptr_t)szMemtest;
    uintptr_t expectedPtrRet = ptr;

    // Call the function and check the result
    uintptr_t result = writeToProcess(dwPid, memory, ptr);
    string sResult(szMemtest, sizeof(szMemtest));
    REQUIRE(result == expectedPtrRet);
    REQUIRE(sResult == memory);
}

TEST_CASE("readFromProcess test") {
    const char szBinaryData[] = "\x00\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00";
    string expectedMemory(szBinaryData,sizeof(szBinaryData));
    DWORD dwPid = GetCurrentProcessId();
    uintptr_t ptr = (uintptr_t)szBinaryData;
    string memory;

    // Call the function and check the result and memory content
    bool result = readFromProcess(dwPid, memory, ptr, sizeof(szBinaryData));
    REQUIRE(result == true);
    REQUIRE(memory == expectedMemory);
}

TEST_CASE("replacestr test") {
    string str = "Hello World!";
    string from = "World";
    string to = "OpenAI";
    bool expectedRet = true;
    string expectedStr = "Hello OpenAI!";
    // Call the function and check the result and modified string
    bool result = replacestr(str, from, to);
    REQUIRE(result == true);
    REQUIRE(str == expectedStr);
}

TEST_CASE("getSyscallNumber test") {
    string invalidApi = "SomeAPI";
    string validApi = "NtAccessCheck"; //This test might fail in order versions of windows, but I don't know how else to test it.
    DWORD sysCall = 0;
    // Call the function and check the result and syscall value
    bool result = getSyscallNumber(invalidApi, &sysCall);
    REQUIRE(result == false);
    result = getSyscallNumber(validApi, &sysCall);
    REQUIRE(result == true);
    REQUIRE(sysCall == 0);
}

TEST_CASE("remoteFree test") {
    uintptr_t toFree = (uintptr_t) VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    REQUIRE(toFree > 0);
    // Call the function and check the result
    bool result = remoteFree(GetCurrentProcessId(), toFree);
    REQUIRE(result == true);
    MEMORY_BASIC_INFORMATION mInfo;
    ZeroMemory(&mInfo, sizeof(mInfo));
    REQUIRE(VirtualQuery((LPCVOID)toFree, &mInfo, sizeof(mInfo)) != 0);
    REQUIRE(mInfo.State == MEM_FREE);
}

TEST_CASE("isValidMemory test") {
    uintptr_t invalidPtr = 0x1000; //Should not be allocated;
    uintptr_t validPtr = (uintptr_t) isValidMemory;
    // Call the function and check the result
    bool result = isValidMemory(invalidPtr);
    REQUIRE(result == false);
    result = isValidMemory(validPtr);
    REQUIRE(result == true);
}


TEST_CASE("manuallyTrigger test") {
    DWORD dwPid = 1234;

    // Call the function (no specific checks for this test case)
    manuallyTrigger(dwPid);
}

void testFunc()
{
    originalCall();
}

/*
TEST_CASE("isOriginalCall test") {
    string sOriginalCall((char*)testFunc,0x100);
    string sOtherFunc((char*)manuallyTrigger, 0x100);
    // Call the function and check the result
    bool result = isOriginalCall((uintptr_t)sOriginalCall.c_str());
    REQUIRE(result == true);
    result = isOriginalCall((uintptr_t)sOtherFunc.c_str());
    REQUIRE(result == false);
}*/

TEST_CASE("IsAddressInTextSection test") {
    uintptr_t address = (uintptr_t)placeJumpToEntry;
    uintptr_t otherValidAddress = (uintptr_t) globalVariable;
    uintptr_t otherInvalidAddress = 0xcaca8888;
    // Call the function and check the result
    bool result = IsAddressInTextSection(address);
    REQUIRE(result == true);
    result = IsAddressInTextSection(otherValidAddress);
    REQUIRE(result == false);
    result = IsAddressInTextSection(otherInvalidAddress);
    REQUIRE(result == false);
}

TEST_CASE("placeJumpToEntry test") {
    string sCode = "SomeCode";
    uint32_t entryOffset = 0x100;
    string expectedModifiedCode("\xE9\x00\x01\x00\x00SomeCode", sCode.size()+5);

    // Call the function and check the modified code
    placeJumpToEntry(sCode, &entryOffset);
    REQUIRE(sCode == expectedModifiedCode);
    REQUIRE(entryOffset == 0x105);
}

/*
TEST_CASE("handleLocalCalls test") {
    //Need to encapsulate this function better to do unit tests.
    std::string sCode = "SomeCode";
    uintptr_t baseMemory = 0x1000;
    std::string sReplacecode = "Replacement";
    uint32_t expectedEntryOffset = 0x100;

    // Call the function and check the result
    uint32_t result = handleLocalCalls(sCode, baseMemory, sReplacecode);
    REQUIRE(result == expectedEntryOffset);
    // Additional checks if needed
}



*/
