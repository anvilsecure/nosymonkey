#include <vector>
uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t* dwGLE, vector<uintptr_t> args);
uintptr_t allocateParam(DWORD dwPid, string sParam);
void freeParam(DWORD dwPid, uintptr_t paramAdd);
