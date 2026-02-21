@echo off
setlocal
set "APPDIR=%~dp0"
set "PY=%APPDIR%.venv\Scripts\python.exe"
set "APP_NAME=hpe-vnc-wall"
set "DIST_APP=%APPDIR%dist\%APP_NAME%"
set "ICON_FILE=%APPDIR%favcon.ico"

if not exist "%PY%" (
  echo Missing venv python. Run setup_venv.bat first.
  pause
  exit /b 1
)

if not exist "%APPDIR%vendor\noVNC\vnc_lite.html" (
  echo Missing noVNC assets. Expected: vendor\noVNC\vnc_lite.html
  pause
  exit /b 1
)

echo Installing build dependency: pyinstaller
"%PY%" -m pip install --upgrade pip
if errorlevel 1 (
  echo pip upgrade failed.
  pause
  exit /b 1
)
"%PY%" -m pip install pyinstaller
if errorlevel 1 (
  echo pyinstaller install failed.
  pause
  exit /b 1
)

if exist "%APPDIR%build" rmdir /S /Q "%APPDIR%build"
if exist "%DIST_APP%" rmdir /S /Q "%DIST_APP%"
if exist "%APPDIR%%APP_NAME%.spec" del /Q "%APPDIR%%APP_NAME%.spec"

echo Building portable EXE...
if exist "%ICON_FILE%" (
  "%PY%" -m PyInstaller --noconfirm --clean --onedir --name "%APP_NAME%" --collect-submodules websockify --icon "%ICON_FILE%" "%APPDIR%wall_server.py"
) else (
  "%PY%" -m PyInstaller --noconfirm --clean --onedir --name "%APP_NAME%" --collect-submodules websockify "%APPDIR%wall_server.py"
)
if errorlevel 1 (
  echo PyInstaller build failed.
  pause
  exit /b 1
)

if not exist "%DIST_APP%\%APP_NAME%.exe" (
  echo Build output not found: %DIST_APP%\%APP_NAME%.exe
  pause
  exit /b 1
)

echo Copying runtime folders (config, data, vendor)...
xcopy /E /I /Y "%APPDIR%config" "%DIST_APP%\config\" >nul
if errorlevel 1 (
  echo Failed to copy config folder.
  pause
  exit /b 1
)
xcopy /E /I /Y "%APPDIR%data" "%DIST_APP%\data\" >nul
if errorlevel 1 (
  echo Failed to copy data folder.
  pause
  exit /b 1
)
xcopy /E /I /Y "%APPDIR%vendor" "%DIST_APP%\vendor\" >nul
if errorlevel 1 (
  echo Failed to copy vendor folder.
  pause
  exit /b 1
)

if exist "%DIST_APP%\data\tokens.txt" del /Q "%DIST_APP%\data\tokens.txt"
if not exist "%DIST_APP%\data\logs" mkdir "%DIST_APP%\data\logs" >nul 2>&1

(
echo @echo off
echo setlocal
echo set "APPDIR=%%~dp0"
echo "%%APPDIR%%%APP_NAME%.exe"
echo pause
) > "%DIST_APP%\run_wall_portable.bat"

echo.
echo Portable build ready:
echo %DIST_APP%
echo.
echo Run:
echo   %DIST_APP%\run_wall_portable.bat
pause
