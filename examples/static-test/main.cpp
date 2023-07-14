#include "debug.hpp"
#include "../../include/nosymonkey.hpp"
#include <iostream>
using namespace std;

/*
This is a general regression test and example to explain how to use local functions.
Local functions are those that exist on your module, and are not referenced on other modules, and are thus called via relative 4 byte calls.
Nosymonkey will copy as little as it can from the .text section of the executable.
--------    --
However!! (And I don't think there's much else I can do about this):
There is no real way (other than running the code) of knowing where your code will return.
I believe this falls into "Halting Problem" territory and unless you guys have some sort of phlebotinum I haven't thought of,
other than a few optimizations the general idea behind this will remain as is.

This is to say: Include local functions in your code at your own risk, as they may reference functions that are no longer valid when Nosymonkey copies it
into you target process.

However: At the expense of more processing time and a bigger final shellcode copied (Up to the size of the .text section of your executable),
You may tweak this if you wish with two functions:

setCopyDepth(): Sets the number of passes for which Nosymonkey will try to include local function calls.
setCopyCodeSize(): There is no real way of knowing at compile time the size of a function, this is set to 0x400 by default, but if your function is small you can reduce it.

*/

const char szCompare[] = "dbgcore.dll";

uintptr_t doSomething(char *szString)
{
    if(szString[0]) return 1;
    return 2;
}

uintptr_t compareAndPrint(int times) //Calls a bunch of local calls, including one defined by us. Tests backwards memory expansion as well.
{
    char *szLocalCompare = new char[sizeof(szCompare)];
    strcpy(szLocalCompare, szCompare);
    int total = 0;
    for(int i = 0; i< times; i++) doSomething(szLocalCompare);
    int compareResult = strcmp(szCompare, szLocalCompare);
    delete [] szLocalCompare;
    return compareResult;
}

int main()
{
    setCopyDepth(3);
    setLogLevel(2);
    cout << copyAndExecWithParams(GetCurrentProcessId(), (LPCVOID) compareAndPrint, nullptr, {6}) << endl;
    return 0;
}
