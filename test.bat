@echo off
setlocal
cd /d "%~dp0"

echo --- building ---
call build.bat
if errorlevel 1 (
    echo --- build failed, aborting tests ---
    exit /b 1
)

echo.
echo --- running tests ---
snapshot.exe --test test_target.exe
exit /b %errorlevel%
