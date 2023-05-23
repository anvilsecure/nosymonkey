# NosyMonkey
API hooking and code injection made easy!

With this library you can easily and **quickly hook** NTDLL "Nt" functions (with direct system calls) or functions from any other library (with shadow loading).
Another awesome functionality of this tool is **Remote Execute:** Just provide it a function or an API and you can execute it in any process you have permission for. You may even pass it up to 10 parameters!

The injection technique uses a hook to **NtTerminateThread** which is executed whenever a thread terminates in a process. Then it calls CreateRemoteThread with an empty thread to trigger this hook. It's a sneakier version of just executing a new thread with your code. The hook then uses direct system call to call the original API. Everything is locked for your threading convenience.

For functions used for hooks, the library processes all the relative calls and relative LEAs and makes them absolute. This is so you may **include strings** and calls to **other APIs** on your replacing functions.

This is also included for the remote execute feature.

## Features

* Hooking "Nt" functions from ntdll.dll (those who context switch) and resume execution with a direct system call.
* Hooking other functions via DLL Shadow loading (loading a copy of the DLL).
* Executing APIs with up to 10 parameters on remote processes.
* Executing your own functions with up to 10 parameters on remote processes.
* Automatic including of API calls and strings on replacing functions (for hooks) and remote execution.
* Other miscelaneous tools.

## Compiling
I've used Clang++ to compile it, you may use `build.cmd` to compile it easily, and then you can include "nosymonkey.hpp" and link with the static library.
You need Clang++ of course and you need to have MSVC++ installed as well. Clang doesn't ship its own windows includes and libraries, so otherwise it will fail.

If you are compiling it by yourself, remember to put the flag `-masm=intel`. At&t syntax kinda sucks...

Do not attempt to compile it for anything other than Windows x64, otherwise be prepared to go down a deep deep rabbit hole.

You can include -DVERBOSE for extended verbosity on the library. Or use the precompiled one.

I use CodeBlocks as my IDE (I know, old habits die hard) that's what those **cbp** files are. You can use it too :)

## Usage
Just link with nosymonkey.lib or nosymonkey_verbose.lib (if you want output to stdout) and include nosymonkey.hpp in your project.
**Make sure to link with advapi32 and psapi (-ladvapi32 -lpsapi).** I will try to remove this requisite in the future.
**You need to call init_nosymonkey() before you do anything.** This is to identify the call to originalCall(). I'll try to remove this requisite in the future as well.

I use C++ strings to handle memory because they are easy to use and you don't have to worry about freeing them.
The exposed APIs so far are:

**bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName)**

Takes a process id, a pointer to a function you'd like to use for your hook and an API name (from ntdll.dll). It overwrites the API in ntdll, redirects to your code and then performs a direct system call to the original API (to resume execution). 

Returns true on success, false on error.

**bool detourAPIHook(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName, string dllName)**

Takes:
* A process ID.
* A pointer to a local function you'd like to use for your hook.
* An API name.
* A dll name.

Returns true on success, false on error.

**uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr)**

Takes a process id, a string with the memory you'd like to write and the target address. If you put 0 as the target address, it will allocate it for you.

Returns the base address of the written data. Or 0 on error.

**bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize)**

Takes a process id, a pointer to a string that will receive the data read, the pointer to the address to be read and the size of the data to be read. 

Returns true on success, false on error.

**bool replacestr(string& str, const string& from, const string& to)**

Takes a pointer to a string to modify, a string to search and replace and a string to replace to.

Returns true on success, false on error.

**bool getSyscallNumber(string apiName, DWORD \*sysCall)**

Takes an API name (from ntdll.dll) and a pointer to a DWORD. Returns the number of the syscall for that specific API (For direct system calling).

Returns true on success, false on error.

**bool remoteFree(DWORD dwPid, uintptr_t ptr)**

Takes a process id and a pointer to allocated memory and frees it.

Returns true on success, false on error.

**void manuallyTrigger(DWORD dwPid)**

Takes a process id and creates an empty thread on the target process. It's used to trigger execution of NtTerminateThread after it had been hooked.

**DWORD getProcessId(string processName)**

Takes a process name and returns its process Id or 0 on failure.

**bool givePrivs(DWORD dwPid)**

Gives the target process ID SE_DEBUG_PRIVILEGE.

Returns true on success, false on error.

**uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t\* dwGLE, vector<uintptr_t> args)**

Takes:
* A process id
* A remote function's address (Obtained fro example with GetProcAddress)
* A pointer to a variable that will receive the GetLastError() result of the remote function call
* A vector of parameters, you can implicitely include them like this {0, 1, 2, null} (See examples).

Returns the return value of the remote call (the remote RAX).

**uintptr_t dupHandle(DWORD dwPid, HANDLE hHandle)**

Takes a process id and a Handle, duplicates it for the remote process and returns it as a uintptr_t.

I know HANDLE is a DWORD but you'll need uintptr_t if you want to pass it as a parameter.

Returns the new HANDLE value or 0 on error.

**uintptr_t copyAndExecWithParams(DWORD dwPid, LPCVOID localFunc, uintptr_t\* dwGLE, vector<uintptr_t> args)**

Takes:
* A process id
* A pointer to a local function you created
* A pointer to a variable that will receive the GetLastError() result of the function call
* A vector of parameters, you can implicitely include them like this {0, 1, 2, null} (See examples).

This function will take your local function, replace calls to APIs (that will be in your process's IAT) and replaces them with absolute calls. It will also replace any strings you include (that would be in other sections of your executable) and insert them shellcode-style. 
It will then copy it to the target process, pass any parameters you specified (up to 10) and then execute it via a sneaky method.

This is basically made so you can create your function on the context of your C++ project and just use it on your remote process without going through any hassle.

Returns the return value of your function (the remote RAX).

## What can I use this for?

* Hooking functions for reverse engineer or analysis.
* Bypassing anti-virus via malware micro-service model (See **LSASS dumper example that bypasses Windows Defender!**).
* Anti-anti-debugging.
* Close handles on other processes.
* Whatever your imagination desires.

## Limitations

* I'm a security engineer not a coder! (Insert StarTrek meme): Sorry about the code war crimes. I tried commenting as much as I could but understanding it may be challenging. If this grabs enough momentum I might do a walkthrough :)
* Threading /should/ work: This was coded with multi-threading taken into consideration; but I haven't extensively tested so I can't be sure.
* This is probably not performance-optimized: This was coded without performance in mind, it works but it's not super performing.
* I haven't wrote unit tests: Examples work a bit like regression tests, but there are no unit tests. I'm gonna try to include them in the future.
* You need to link against -ladvapi32 and -lpsapi.
* ~~You need to call init_nosymonkey() before you do anything.~~
* detourAPIHook creates a copy of the DLL. In the future I might use MemoryModule to reflectively load a copy.

## Feedback

I'm open to receiving feedback! I'm always learning so please feel free to submit issues and pull requests. I'll try to get to them as much as I can.

## Troubleshooting

* I'm trying to hook api X from kernel32.dll and it crashes with STACK_OVERFLOW: Kernel32.dll is now just a wrapper for Kernelbase.dll. Use the latter.
* Hooking Rtl* from ntdll.dll doesn't work with hookAPIDirectSyscall: Rtl are run-time libraries that are run on user space. There is no context switch and no system call. For this reason you cannot use direct system calls. You may only do this with functions that start with "Nt" or "Zw".
* It crashes! Send me an issue with the source that's failing for you and I'll do my best to help out.
