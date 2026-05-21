@echo off
setlocal

set CL_FLAGS=/nologo /W3 /O2 /EHsc
set LINK_FLAGS=/nologo

echo --- building ss_hooks.dll ---
cl %CL_FLAGS% /LD ss_hooks.cpp /Fe:ss_hooks.dll ^
    /link %LINK_FLAGS% psapi.lib
if errorlevel 1 goto fail

echo --- building snapshot.exe ---
cl %CL_FLAGS% snapshot.cpp /Fe:snapshot.exe ^
    /link %LINK_FLAGS% advapi32.lib dbghelp.lib psapi.lib user32.lib shell32.lib
if errorlevel 1 goto fail

echo --- building test_target.exe ---
cl %CL_FLAGS% test_target.cpp /Fe:test_target.exe ^
    /link %LINK_FLAGS%
if errorlevel 1 goto fail

echo --- build OK ---
exit /b 0

:fail
echo --- build FAILED ---
exit /b 1
