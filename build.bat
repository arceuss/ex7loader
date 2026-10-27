@echo off
setlocal enabledelayedexpansion
REM ===========================================================================
REM build.bat - compile explorer7.dll (x64). Self-contained: needs only MSVC
REM             (Build Tools for Visual Studio, "Desktop development with C++")
REM             and the Windows SDK. No phnt, no other dependencies.
REM ===========================================================================

set "SRC=%~dp0explorer7.c"
set "OUT=%~dp0explorer7.dll"

REM --- If cl.exe is already on PATH (e.g. run from an x64 Native Tools prompt),
REM     skip environment setup.
where cl.exe >nul 2>nul && goto :compile

REM --- Otherwise locate a VS / Build Tools install with vswhere and import its env.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [!] vswhere.exe not found. Install "Build Tools for Visual Studio" with the
  echo     C++ workload, or open an "x64 Native Tools Command Prompt for VS" and
  echo     run this script from there.
  exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
  echo [!] No MSVC C++ toolset found. Install the "Desktop development with C++" workload.
  exit /b 1
)
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" (
  echo [!] vcvarsall.bat missing under "%VSPATH%".
  exit /b 1
)

echo [*] Using MSVC at "%VSPATH%"
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
where cl.exe >nul 2>nul || (echo [!] cl.exe still not found after env setup. & exit /b 1)

:compile
echo [*] Compiling explorer7.dll (x64) ...
pushd "%~dp0"
cl /nologo /O2 /W3 /GS- /Zl "%SRC%" /LD /Fe:"%OUT%" /link /NODEFAULTLIB /ENTRY:DllMain ntdll.lib
set "RC=%ERRORLEVEL%"
del /q "%~dp0explorer7.obj" "%~dp0explorer7.lib" "%~dp0explorer7.exp" >nul 2>nul
popd
if not "%RC%"=="0" (
  echo [!] Build failed ^(exit %RC%^).
  exit /b %RC%
)

echo.
echo [*] Built: %OUT%
echo [*] Install steps (as Administrator):
echo       1. copy "%OUT%" "%windir%\System32\explorer7.dll"
echo       2. put the Win7 x64 explorer.exe at  C:\explorer7\explorer.exe
echo       3. import explorer7_install.reg
echo       4. sign out / restart explorer.exe
endlocal
