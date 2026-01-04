@echo off
REM Build script for creating standalone executable with PyInstaller (Windows)
REM Usage: build-executable.bat

setlocal enabledelayedexpansion

echo ==========================================
echo Building ssl-tester executable
echo ==========================================

REM Check if we're in a virtual environment
if "%VIRTUAL_ENV%"=="" (
    echo WARNING: Not in a virtual environment. Creating one...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Virtual environment activated.
)

REM Check Python version
python --version
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.11 or higher.
    exit /b 1
)

REM Install/upgrade dependencies
echo.
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -e ".[build]"

REM Clean previous builds
echo.
echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist ssl-tester.spec del /q ssl-tester.spec

REM Build executable
echo.
echo Building executable with PyInstaller...
pyinstaller ^
    --onefile ^
    --name ssl-tester ^
    --hidden-import=ssl_tester ^
    --hidden-import=ssl_tester.cli ^
    --hidden-import=ssl_tester.network ^
    --hidden-import=ssl_tester.certificate ^
    --hidden-import=ssl_tester.chain ^
    --hidden-import=ssl_tester.crl ^
    --hidden-import=ssl_tester.ocsp ^
    --hidden-import=ssl_tester.reporter ^
    --hidden-import=ssl_tester.models ^
    --hidden-import=ssl_tester.exceptions ^
    --hidden-import=ssl_tester.http_client ^
    --hidden-import=ssl_tester.retry ^
    --hidden-import=cryptography ^
    --hidden-import=cryptography.hazmat ^
    --hidden-import=cryptography.hazmat.primitives ^
    --hidden-import=cryptography.hazmat.backends ^
    --hidden-import=cryptography.hazmat.backends.default_backend ^
    --hidden-import=httpx ^
    --hidden-import=httpx._client ^
    --hidden-import=typer ^
    --hidden-import=typer.core ^
    --hidden-import=certifi ^
    --hidden-import=idna ^
    --collect-all=cryptography ^
    --collect-all=certifi ^
    --console ^
    --clean ^
    src\ssl_tester\cli.py

REM Check if build was successful
if exist "dist\ssl-tester.exe" (
    echo.
    echo ==========================================
    echo Build successful!
    echo ==========================================
    
    echo Executable: dist\ssl-tester.exe
    echo.
    echo Testing executable...
    dist\ssl-tester.exe --help
    
    echo.
    echo Executable is ready in dist\
) else (
    echo.
    echo ERROR: Build failed - executable not found
    exit /b 1
)

endlocal


