@echo off
@cls
@where clang++ > nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Clang doesn't seem to be installed. 
    ECHO Make sure both Clang and MSVC are installed. You need the libraries from MSVC.
    exit /b
)
echo Cleaning previous build artifacts...
@del build\obj\src\*.o > nul 2>&1
@del build\bin\*.* /Y > nul 2>&1
echo Compiling obj files...
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\detourAPIHook.cpp -o build\obj\src\detourAPIHook.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\directSyscalHook.cpp -o build\obj\src\directSyscalHook.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\dllShadowLoad.cpp -o build\obj\src\dllShadowLoad.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\helpers.cpp -o build\obj\src\helpers.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\privileges.cpp -o build\obj\src\privileges.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\process.cpp -o build\obj\src\process.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\remoteExecute.cpp -o build\obj\src\remoteExecute.o
clang++.exe -m64 -O2 -std=c++20 -masm=intel -Isrc -c src\shellcodePrepare.cpp -o build\obj\src\shellcodePrepare.o

echo Compiling library...
llvm-ar.exe r build\bin\nosymonkey.lib build\obj\src\detourAPIHook.o build\obj\src\directSyscalHook.o build\obj\src\dllShadowLoad.o build\obj\src\helpers.o build\obj\src\privileges.o build\obj\src\process.o build\obj\src\remoteExecute.o build\obj\src\shellcodePrepare.o
