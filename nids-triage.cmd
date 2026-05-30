@echo off
setlocal
set "SCRIPT_DIR=%~dp0scripts"
if not exist "%SCRIPT_DIR%\run_local_triage.cmd" exit /b 1
call "%SCRIPT_DIR%\run_local_triage.cmd" %*
set "EXIT_CODE=%ERRORLEVEL%"
endlocal
exit /b %EXIT_CODE%
