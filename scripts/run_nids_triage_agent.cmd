@echo off
setlocal
set "RUNNER=%~dp0run_nids_triage_agent.ps1"
if not exist "%RUNNER%" exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -File "%RUNNER%" %*
endlocal
