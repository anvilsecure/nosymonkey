#include <windows.h>
#include <stdio.h>
#include "helpers.hpp"

BOOL SetPrivilege(HANDLE hToken,LPCTSTR lpszPrivilege,BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (LookupPrivilegeValue(NULL,lpszPrivilege,&luid))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        else tp.Privileges[0].Attributes = 0;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) )
        {
            if (GetLastError() != ERROR_NOT_ALL_ASSIGNED)
            {
                return true;
            }
            debugcry("AdjustTokenPrivileges");
        }
        debugcry("AdjustTokenPrivileges");
    }
    debugcry("LookupPrivilegeValue");
    return false;
}

bool givePrivs(DWORD dwPid)
{
    HANDLE hToken = INVALID_HANDLE_VALUE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
    if(hProcess)
    {
        if(OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
        {
            SetPrivilege(hToken, "SeDebugPrivilege", true);
            CloseHandle(hToken);
            return true;
        }
        debugcry("OpenProcessToken");
        CloseHandle(hProcess);
    }
    debugcry("OpenProcess");
    return false;
}
