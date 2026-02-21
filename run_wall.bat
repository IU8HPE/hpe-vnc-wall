@echo off
setlocal
set "APPDIR=%~dp0"
set "PY=%APPDIR%.venv\Scripts\python.exe"
set "PORT=8090"

if not exist "%PY%" (
  echo Missing venv. Run setup_venv.bat first.
  pause
  exit /b 1
)

for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":%PORT% .*LISTENING"') do (
  echo Port %PORT% is already in use by PID %%P.
  echo Stop that process first, then run again.
  pause
  exit /b 1
)

"%PY%" "%APPDIR%wall_server.py"

pause
