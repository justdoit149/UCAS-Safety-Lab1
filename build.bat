@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"

"%PYTHON%" -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
    echo [ERROR] PyInstaller is not installed.
    echo Run: "%PYTHON%" -m pip install -r requirements-build.txt
    exit /b 1
)

echo [1/2] Cleaning and packaging, first build takes about 1-2 minutes...
rem Exclude optional heavy libraries that this program does not use.
rem If they are installed, PyInstaller drags them into the graph and the
rem build can grow from about one minute to more than ten minutes.
"%PYTHON%" -m PyInstaller ^
    --noconfirm --clean --windowed --onedir ^
    --name Lab1A-Sniffer ^
    --exclude-module plotly ^
    --exclude-module kaleido ^
    --exclude-module pandas ^
    --exclude-module matplotlib ^
    --exclude-module scipy ^
    --exclude-module IPython ^
    --exclude-module jupyter ^
    --exclude-module notebook ^
    --exclude-module PyQt5 ^
    --exclude-module PyQt6 ^
    --exclude-module PySide2 ^
    --exclude-module tkinter ^
    main.py
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See the PyInstaller output above.
    exit /b 1
)

if not exist "dist\Lab1A-Sniffer\Lab1A-Sniffer.exe" (
    echo [ERROR] dist\Lab1A-Sniffer\Lab1A-Sniffer.exe was not created.
    exit /b 1
)

echo.
echo [2/2] Build complete:
echo   dist\Lab1A-Sniffer\Lab1A-Sniffer.exe
echo.
echo The target machine needs Npcap 1.90 with WinPcap compatibility mode.
echo Copy the whole dist\Lab1A-Sniffer directory, not only the exe.
endlocal
