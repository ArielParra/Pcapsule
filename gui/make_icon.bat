@echo off

:: Delete existing executable if it exists
if exist "pcapsule-Windows.exe" (
    del "pcapsule-Windows.exe"
)

:: Create icon resource
windres icon.rc -O coff -o icon.res
if errorlevel 1 (
    echo Failed to generate icon resource.
    pause
    exit /b 1
)

:: Compile the executable
echo Compiling pcapsule-Windows.exe...
g++.exe -o pcapsule-Windows.exe main.cpp -lwpcap -lws2_32 -lraylib -mwindows -w -std=c++17 -Ofast -funroll-loops -mavx2 icon.res
if errorlevel 1 (
    echo Compilation failed.
    pause
    exit /b 1
)

:: Notify the user of success
if exist "%temp%\tmp.vbs" (
    del "%temp%\tmp.vbs"
)
echo x=msgbox("pcapsule-Windows.exe successfully created!", 64, "Success!") > "%temp%\tmp.vbs"
start %temp%\tmp.vbs

exit /b 0
