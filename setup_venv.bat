@echo off
setlocal
set "APPDIR=%~dp0"

if not exist "%APPDIR%.venv" (
  py -3 -m venv "%APPDIR%.venv"
)

"%APPDIR%.venv\Scripts\python.exe" -m pip install --upgrade pip
"%APPDIR%.venv\Scripts\python.exe" -m pip install -r "%APPDIR%requirements.txt"

echo.
echo venv ready.
echo Run: run_wall.bat
pause
