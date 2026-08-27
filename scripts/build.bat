@echo off
rem
rem Configure and build with MSVC on Windows.
rem
rem MSVC needs its environment set up before cl.exe can find its own headers, and
rem vcvars64.bat is the only supported way to do it. Rather than have every
rem contributor remember which developer prompt to open, this script finds the
rem toolchain with vswhere (which ships with every VS install since 2017) and
rem applies it, so a plain `scripts\build.bat` works from any shell.
rem
rem   scripts\build.bat              configure + build the dev preset
rem   scripts\build.bat release      configure + build a named preset
rem   scripts\build.bat dev test     configure, build, then run the test suite
rem
setlocal EnableDelayedExpansion

set PRESET=%1
if "%PRESET%"=="" set PRESET=dev
set ACTION=%2

set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
    echo error: vswhere.exe not found. Install Visual Studio 2019 or later,
    echo        or the standalone Build Tools package.
    exit /b 1
)

rem -latest so a machine with several versions installed picks the newest, and
rem -requires so a VS install without the C++ workload is not selected and then
rem found to be missing cl.exe halfway through the build.
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * ^
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
    -property installationPath`) do set VSPATH=%%i

if "%VSPATH%"=="" (
    echo error: no Visual Studio install with the C++ toolset was found.
    exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo error: vcvars64.bat failed.
    exit /b 1
)

rem Ninja parses /showIncludes to track headers and unity-included sources.
rem Force the stable English prefix so a localised MSVC installation cannot
rem silently produce empty dependency sets through a code-page mismatch.
set VSLANG=1033

echo -- toolchain: %VSPATH%
cl 2>&1 | findstr /C:"Version"

cmake --preset %PRESET% || exit /b 1
cmake --build --preset %PRESET% || exit /b 1

if /i "%ACTION%"=="test" (
    ctest --preset %PRESET% || exit /b 1
)

endlocal
