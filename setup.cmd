@echo off
setlocal
chcp 65001 >nul
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -X utf8 "%~dp0csu_portal_watchdog.py" setup --install
) else (
  where python >nul 2>&1
  if errorlevel 1 (
    echo Python 3.10 or later is required. Install Python and run this file again.
  ) else (
    python -X utf8 "%~dp0csu_portal_watchdog.py" setup --install
  )
)
echo.
pause
