@echo off
setlocal
set "APPDIR=%~dp0"
set "SERVICE_NAME=VNCWallStandalone"
set "NSSM=%NSSM_PATH%"
set "PYTHON=%APPDIR%.venv\Scripts\python.exe"

if "%NSSM%"=="" set "NSSM=C:\nssm\win64\nssm.exe"
if not exist "%NSSM%" (
  for %%I in (nssm.exe) do set "NSSM=%%~$PATH:I"
)

if not exist "%NSSM%" (
  echo Missing NSSM. Set NSSM_PATH or add nssm.exe to PATH.
  pause
  exit /b 1
)
if not exist "%PYTHON%" (
  echo Missing venv python. Run setup_venv.bat first.
  pause
  exit /b 1
)

if not exist "%APPDIR%data\logs" mkdir "%APPDIR%data\logs" >nul 2>&1

"%NSSM%" install "%SERVICE_NAME%" "%PYTHON%" "\"%APPDIR%wall_server.py\""
"%NSSM%" set "%SERVICE_NAME%" AppDirectory "%APPDIR%"
"%NSSM%" set "%SERVICE_NAME%" DisplayName "VNC Wall Standalone"
"%NSSM%" set "%SERVICE_NAME%" Description "Generic multi-host VNC wall dashboard"
"%NSSM%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START
"%NSSM%" set "%SERVICE_NAME%" AppStdout "%APPDIR%data\logs\service_out.log"
"%NSSM%" set "%SERVICE_NAME%" AppStderr "%APPDIR%data\logs\service_err.log"
"%NSSM%" restart "%SERVICE_NAME%"

echo Service installed/restarted: %SERVICE_NAME%
pause
