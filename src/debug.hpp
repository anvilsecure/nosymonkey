#include <iostream>
#include <string>
#include <windows.h>
#ifdef VERBOSE
#define debugcry(s) else cout << "Error in " << s << " GLE: " << (dec) << GetLastError() << endl;
#else
#define debugcry(s)
#endif // VERBOSE
#ifndef __clang__
#error "You should compile this with Clang. Other compilers have not been tried"
#endif // __clang__
#ifndef _WIN64
#error "This is for Windows! If you try to compile it for linux you're gonna fall into a deep rabbit hole..."
#endif // __clang__
using namespace std;
