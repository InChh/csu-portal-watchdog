@echo off
setlocal
chcp 65001 >nul
if not exist "%~dp0csu-portal-watchdog.exe" (
  echo Standalone EXE is missing. Download or clone the complete repository.
  goto finish
)
"%~dp0csu-portal-watchdog.exe" setup --install
:finish
echo.
pause
