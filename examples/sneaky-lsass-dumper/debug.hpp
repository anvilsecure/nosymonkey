#include <iostream>
#include <string>
#include <windows.h>
#ifdef VERBOSE
#define debugcry(s) else cout << "Error in " << s << " GLE: " << (dec) << GetLastError() << endl;
#else
#define debugcry(s)
#endif // VERBOSE
using namespace std;

