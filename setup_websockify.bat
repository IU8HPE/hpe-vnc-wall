@echo off
setlocal
set "APPDIR=%~dp0"
set "PY=%APPDIR%.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo Missing venv. Run setup_venv.bat first.
  pause
  exit /b 1
)

"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install websockify

pause
