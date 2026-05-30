@echo off
setlocal
set "PYTHON=%~dp0..\.venv\Scripts\python.exe"
set "REPO_ROOT=%~dp0.."
if not exist "%REPO_ROOT%\scripts\run_local_triage.py" exit /b 1
pushd "%REPO_ROOT%" >nul
if exist "%PYTHON%" (
  "%PYTHON%" -m scripts.run_local_triage %*
) else (
  python -m scripts.run_local_triage %*
)
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul
endlocal
exit /b %EXIT_CODE%
