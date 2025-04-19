@echo off
set ICON_FILENAME=icon
set ICON_FILE=%ICON_FILENAME%.ico
set RC_FILE=%ICON_FILENAME%.rc
set RES_FILE=%ICON_FILENAME%.res

if not exist "%ICON_FILE%" (
    echo Error: %ICON_FILE% not found.
    exit /b 1
)

echo Creating resource script...
(
    echo ICON_RESOURCE ICON "%ICON_FILE%"
    echo.
    echo 1 VERSIONINFO
    echo FILEVERSION 1,0,0,0
    echo PRODUCTVERSION 1,0,0,0
    echo BEGIN
    echo   BLOCK "StringFileInfo"
    echo   BEGIN
    echo     BLOCK "080904E4"
    echo     BEGIN
    echo       VALUE "CompanyName", "UAA"
    echo       VALUE "FileDescription", "Pcapsule GUI"
    echo       VALUE "FileVersion", "1.0"
    echo       VALUE "InternalName", "pcapsule"
    echo       VALUE "LegalCopyright", "MIT"
    echo       VALUE "OriginalFilename", "pcapsule_Windows.exe"
    echo       VALUE "ProductName", "pcapsule"
    echo       VALUE "ProductVersion", "1.0"
    echo     END
    echo   END
    echo   BLOCK "VarFileInfo"
    echo   BEGIN
    echo     VALUE "Translation", 0x809, 1252
    echo   END
    echo END
) > "%RC_FILE%"


echo Compiling resource script to %RES_FILE%...
windres "%RC_FILE%" -O coff -o "%RES_FILE%"
if errorlevel 1 (
    echo Failed to generate icon resource.
    exit /b 1
)

:: Success message
echo Icon resource %RES_FILE% created successfully.
