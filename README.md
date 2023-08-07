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

I use C++ strings to handle memory because they are easy to use and you don't have to worry about freeing them.
The exposed APIs so far are:

### hookAPIDirectSysCall:

```C++
bool hookAPIDirectSyscall(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName);

/*
Takes a process id, a pointer to a function you'd like to use for your hook and an API name (from ntdll.dll). It overwrites the API in ntdll, redirects to your code and then performs a direct system call to the original API (to resume execution). 

Returns true on success, false on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessID of the program in which the hook is going to be placed. Need to have permissions on the target process.
* LPVOID lpShellCodeFunc: Pointer to the function that will act as the replacer on the hook.
* string apiName: API from ntdll.dll that we'll hook. Needs to be a context-switching API (Starting with "Nt"), otherwise we can't do a direct system call.

#### Return Value:
Returns true on success, false on error. 

Possible causes of error can be:
* Lack of privileges in target process.
* Process not found.
* API not recognized or not context-switching.

Increase error verbosity calling to **setLogLevel()** for more information.

### detourAPIHook:

```C++
bool detourAPIHook(DWORD dwPid, LPVOID lpShellCodeFunc, string apiName, string dllName);

/*
Takes:
* A process ID.
* A pointer to a local function you'd like to use for your hook.
* An API name.
* A dll name.

Returns true on success, false on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessID of the program in which the hook is going to be placed. Need to have permissions on the target process.
* LPVOID lpShellCodeFunc: Pointer to the function that will act as the replacer on the hook.
* string apiName: API from the DLL referenced by the parameter *dllName* to be hooked.
* string dllName: DLL that contains the API to be hooked.

#### Return Value:
Returns true on success, false on error. 

Possible causes of error can be:
* Lack of privileges in target process.
* Process not found.
* API does not exist on the target DLL.
* DLL cannot be found, opened or loaded.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* On newer versions of Windows, functions from **kernel32.dll** are actually on **kernelbase.dll**. If your program is crashing with a STACK_OVERRUN exception, make sure to reference **kernelbase.dll**. 
* The DLL will be loaded a second time by copying it with a different name and loading it. In the future I'll try to implement reflective DLL loading to get a second version of the DLL. 
* Non-ASLR-enabled libraries will fail to load a second time, because they have a fixed base address.

### writeToProcess:

```C++
uintptr_t writeToProcess(DWORD dwPid, string memory, uintptr_t ptr);

/*
Takes a process id, a string with the memory you'd like to write and the target address. If you put 0 as the target address, it will allocate it for you.

Returns the base address of the written data. Or 0 on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessID of the program in which memory will be written. Need to have permissions on the target process.
* string memory: A string containing the memory to be written.
* uintptr_t ptr: Pointer to the memory address to write. If it's set to **0** then memory will be allocated on the target process.

#### Return Value:
Returns the base address of the data written, or 0 on error.


Possible causes of error can be:
* Lack of privileges in target process.
* Process not found.
* Target memory address is invalid.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* If the target's memory protection prevents writing, protection will be temporarily set to PAGE_EXECUTE_READWRITE and then will be restored to its original value.
* You may initialize strings with binary data by specifying the size of the binary data as the second parameter of the constructor:

```C++
char szBinaryData[] = "\x00\xBA\xCA\x90\x00";

string sBinaryData(szBinaryData, sizeof(szBinaryData));
```

### readFromProcess:
```C++
bool readFromProcess(DWORD dwPid, string &memory, uintptr_t ptr, DWORD dwSize);

/*
Takes a process id, a pointer to a string that will receive the data read, the pointer to the address to be read and the size of the data to be read. 

Returns true on success, false on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessID of the program from which memory will be read. Need to have permissions on the target process.
* string memory: Reference to a string that will receive the data read.
* uintptr_t ptr: Pointer to the memory address to read from.
* DWORD dwSize: Size of data to read.

#### Return Value:
Returns true on success, false on error.

Possible causes of error can be:
* Lack of privileges in target process.
* Process not found.
* Target memory address is invalid.

Increase error verbosity calling to **setLogLevel()** for more information.

### remoteFree:
```C++
bool remoteFree(DWORD dwPid, uintptr_t ptr);

/*
Takes a process id and a pointer to allocated memory and frees it.

Returns true on success, false on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessID of the program that holds the memory page to be freed. Need to have permissions on the target process.
* uintptr_t ptr: Pointer to the memory address to be freed.

#### Return Value:
Returns true on success, false on error. 

Possible causes of error can be:
* Lack of privileges in target process.
* Process not found.
* Target memory address is invalid.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* Will fail unless **ptr** is the base address of a page.
* Does not support granular region memory management.

### getProcessId:

```C++
DWORD getProcessId(string processName);

// Takes a process name and returns its process Id or 0 on error.
```

#### Parameters:
* string processName: Case-sensitive name of the process.

#### Return Value:
The process Id of the first process found with the name supplied, or 0 on error.

Possible causes of error can be:
* Process cannot be found.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* Will return the first process it founds with the name specified.


### givePrivs:

```C++
bool givePrivs(DWORD dwPid);

/*
Enables the privilege SE_DEBUG_PRIVILEGE in the target process ID.

Returns true on success, false on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessId of the process that will have SE_DEBUG_PRIVILEGE enabled.

#### Return Value:
Returns true on success, false on error.

Possible causes of error can be:
* Process cannot be found.
* Not enough privileges to open process (you may need to give your own process SE_DEBUG_PRIVILEGE first).
* The target process does not hold the SE_DEBUG_PRIVILEGE privilege.

Increase error verbosity calling to **setLogLevel()** for more information.

### execWithParams:

```C++
uintptr_t execWithParams(DWORD dwPid, uintptr_t remoteFunc, uintptr_t* dwGLE, vector<uintptr_t> args);

/*
Executes a function pointer passing it up to 10 arguments on a remote function, optionally obtaining the last GetLastError() value.

Takes:
* A process id
* A remote function's address (Obtained fro example with GetProcAddress)
* A pointer to a variable that will receive the GetLastError() result of the remote function call
* A vector of parameters, you can implicitely include them like this {0, 1, 2, null} (See examples).

*/
```

#### Parameters:
* DWORD dwPid: ProcessId of the process in which the function will be executd.
* uintptr_t remoteFunc: Memory address of the start of the target function.
* uintptr_t *dwGLE: Pointer to variable that will receive the last vaue of GetLastError(). Set to NULL if not needed.
* vector<uintptr_t> args: A vector containing up to 10 parameters that will be passed to the target function.

#### Return Value:
Returns the return value of the remote call (the remote RAX), or 0 on error.

Possible causes of error can be:
* Process cannot be found.
* Not enough privileges to open process.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* The caller is responsible for ensuring that the memory addresses provided either in **remoteFunc** or as one of the values in **args** are valid. Invalid values will likely crash the target process.
* I know that returning 0 on error is not the prettiest of patterns. In the future I'll refactor the function so it returns a boolean and the remote RAX as a value in a pointer parameter.
* You can pass parameters as an implicity vector {0,1,2}.

### copyAndExecWithParams:

```C++
uintptr_t copyAndExecWithParams(DWORD dwPid, LPCVOID localFunc, uintptr_t* dwGLE, vector<uintptr_t> args);

/*
Takes:
* A process id
* A pointer to a local function you created
* A pointer to a variable that will receive the GetLastError() result of the function call
* A vector of parameters, you can implicitely include them like this {0, 1, 2, null} (See examples).

This function will take your local function, replace calls to APIs (that will be in your process's IAT) and replaces them with absolute calls. It will also replace any strings you include (that would be in other sections of your executable) and insert them shellcode-style. 
It will then copy it to the target process, pass any parameters you specified (up to 10) and then execute it via a sneaky method.

This is basically made so you can create your function on the context of your C++ project and just use it on your remote process without going through any hassle.

Returns the return value of your function (the remote RAX).

*/
```

#### Parameters:
* DWORD dwPid: ProcessId of the process in which the function will be executd.
* uintptr_t localFunc: Pointer to a local function you created.
* uintptr_t *dwGLE: Pointer to variable that will receive the last vaue of GetLastError(). Set to NULL if not needed.
* vector<uintptr_t> args: A vector containing up to 10 parameters that will be passed to the target function.

#### Return Value:
Returns the return value of the remote call (the remote RAX), or 0 on error.

Possible causes of error can be:
* Process cannot be found.
* Not enough privileges to open process.
* Cannot prepare the function to be copied.

Increase error verbosity calling to **setLogLevel()** for more information.

#### Remarks:
* The caller is responsible for ensuring that the memory addresses provided as one of the values in **args** are valid. Invalid values will likely crash the target process.
* I know that returning 0 on error is not the prettiest of patterns. In the future I'll refactor the function so it returns a boolean and the remote RAX as a value in a pointer parameter.
* You can pass parameters as an implicity vector {0,1,2}.

### dupHandle:

```C++
uintptr_t dupHandle(DWORD dwPid, HANDLE hHandle);

/*
Takes a process id and a Handle, duplicates it for the remote process and returns it as a uintptr_t.

I know HANDLE is a DWORD but you'll need uintptr_t if you want to pass it as a parameter.

Returns the new HANDLE value or 0 on error.
*/
```

#### Parameters:
* DWORD dwPid: ProcessId of the process in which the function will be executd.
* HANDLE hHandle: Handle to be copied on the target process.

#### Return Value:
Returns the new HANDLE value or 0 on error.

Possible causes of error can be:
* Process cannot be found.
* Not enough privileges to open process.
* HANDLE is invalid.

Increase error verbosity calling to **setLogLevel()** for more information.

### setLogLevel:

```C++
void setLogLevel(int newLogLevel);

/*
Sets the log verbosity level.
Does not return a value
/*

```

#### Parameters:
* int newLogLevel: Can take one of the following values:
    * (0x0): No logging.
    * (0x1): General logging verbosity. Default value.
    * (0x2): Informational logging verbosity.
    * (0x3): Debug logging verbosity.

#### Return Value:
This function does not return a value and does not fail.

### setCopyDepth:

```C++
void setCopyDepth(uint32_t newCopyDepth);

/*
Sets the amount of times Nosymonkey will try to determine the size of the code to be copied with heuristics.
Nosymoney will walk the code, find all of the local calls and increase the start and end of the copied code. This function controls the amount of times this heuristic function will be ran.
A higher value will result in more time and more bytes copied.
/*

```

#### Parameters:
* uint32_t newCopyDepth: Amount of times the heuristics will be run. Default is 1, set to 0 to disable the heuristics (If you are not using statically-linked functions).

#### Return Value:
This function does not return a value and does not fail.

### setCopyCodeSize:

```C++
void setCopyCodeSize(int newCopyCodeSize);

/*
Sets the size of the maximum code copied by Nosymonkey, in bytes. 
Since it's not possible to determine the end of a function at compile or execution time, this value hast to be determined by the user.
/*

```

#### Parameters:
* uint32_t newCopyCodeSize: Size in bytes of the code copied. Default is 0x400.

#### Return Value:
This function does not return a value and does not fail.


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
* You need to link against -ladvapi32 and -lpsapi.
* detourAPIHook creates a copy of the DLL. In the future I might use MemoryModule to reflectively load a copy.
* Support for local calls is limited. I'll try to improve on this process in the future.

## Feedback

I'm open to receiving feedback! I'm always learning so please feel free to submit issues and pull requests. I'll try to get to them as much as I can.

## Troubleshooting

* I'm trying to hook api X from kernel32.dll and it crashes with STACK_OVERFLOW: Kernel32.dll is now just a wrapper for Kernelbase.dll. Use the latter.
* Hooking Rtl* from ntdll.dll doesn't work with hookAPIDirectSyscall: Rtl are run-time libraries that are run on user space. There is no context switch and no system call. For this reason you cannot use direct system calls. You may only do this with functions that start with "Nt" or "Zw".
* It crashes! Send me an issue with the source that's failing for you and I'll do my best to help out.

