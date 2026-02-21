@echo off
setlocal
set "SERVICE_NAME=VNCWallStandalone"
set "NSSM=%NSSM_PATH%"

if "%NSSM%"=="" set "NSSM=C:\nssm\win64\nssm.exe"
if not exist "%NSSM%" (
  for %%I in (nssm.exe) do set "NSSM=%%~$PATH:I"
)

if not exist "%NSSM%" (
  echo Missing NSSM. Set NSSM_PATH or add nssm.exe to PATH.
  pause
  exit /b 1
)

"%NSSM%" stop "%SERVICE_NAME%"
"%NSSM%" remove "%SERVICE_NAME%" confirm
echo Service removed: %SERVICE_NAME%
pause
