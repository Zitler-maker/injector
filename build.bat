@echo off
setlocal enabledelayedexpansion
set "ROOT=%~dp0"
set "BUILD=%ROOT%build"

set "CMAKE="
for %%I in (cmake.exe) do if not "%%~$PATH:I"=="" set "CMAKE=%%~$PATH:I"
if not defined CMAKE (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" (
        for /f "usebackq delims=" %%P in (`"!VSWHERE!" -latest -products * -property installationPath`) do (
            if exist "%%P\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
                set "CMAKE=%%P\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
            )
        )
    )
)
if not defined CMAKE (
    echo [ERROR] cmake not found in PATH or Visual Studio installation
    exit /b 1
)

"%CMAKE%" -S "%ROOT%." -B "%BUILD%" -A x64 || exit /b 1
"%CMAKE%" --build "%BUILD%" --config Release --parallel || exit /b 1

echo [INFO] built: %ROOT%dist\DLLInjector.exe (standalone GUI, everything embedded)
echo [INFO] built: %BUILD%\Release\injector.exe (GUI)
echo [INFO] built: %BUILD%\Release\injector-cli.exe (console)
echo [INFO] built: %BUILD%\Release\sample_dll.dll
exit /b 0
