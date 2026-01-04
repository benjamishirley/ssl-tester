#!/bin/bash
# Build script for creating standalone executable with PyInstaller
# Usage: ./build-executable.sh

set -e  # Exit on error

echo "=========================================="
echo "Building ssl-tester executable"
echo "=========================================="

# Check if we're in a virtual environment
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "WARNING: Not in a virtual environment. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Virtual environment activated."
fi

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Install/upgrade dependencies
echo ""
echo "Installing dependencies..."
pip install --upgrade pip
pip install -e ".[build]"

# Clean previous builds
echo ""
echo "Cleaning previous builds..."
rm -rf build/ dist/ *.spec 2>/dev/null || true

# Build executable
echo ""
echo "Building executable with PyInstaller..."
pyinstaller \
    --onefile \
    --name ssl-tester \
    --hidden-import=ssl_tester \
    --hidden-import=ssl_tester.cli \
    --hidden-import=ssl_tester.network \
    --hidden-import=ssl_tester.certificate \
    --hidden-import=ssl_tester.chain \
    --hidden-import=ssl_tester.crl \
    --hidden-import=ssl_tester.ocsp \
    --hidden-import=ssl_tester.reporter \
    --hidden-import=ssl_tester.models \
    --hidden-import=ssl_tester.exceptions \
    --hidden-import=ssl_tester.http_client \
    --hidden-import=ssl_tester.retry \
    --hidden-import=cryptography \
    --hidden-import=cryptography.hazmat \
    --hidden-import=cryptography.hazmat.primitives \
    --hidden-import=cryptography.hazmat.backends \
    --hidden-import=cryptography.hazmat.backends.default_backend \
    --hidden-import=httpx \
    --hidden-import=httpx._client \
    --hidden-import=typer \
    --hidden-import=typer.core \
    --hidden-import=certifi \
    --hidden-import=idna \
    --collect-all=cryptography \
    --collect-all=certifi \
    --console \
    --clean \
    src/ssl_tester/cli.py

# Check if build was successful
if [ -f "dist/ssl-tester" ] || [ -f "dist/ssl-tester.exe" ]; then
    echo ""
    echo "=========================================="
    echo "Build successful!"
    echo "=========================================="
    
    # Show file size
    if [ -f "dist/ssl-tester" ]; then
        size=$(du -h dist/ssl-tester | cut -f1)
        echo "Executable: dist/ssl-tester ($size)"
    elif [ -f "dist/ssl-tester.exe" ]; then
        size=$(du -h dist/ssl-tester.exe | cut -f1)
        echo "Executable: dist/ssl-tester.exe ($size)"
    fi
    
    echo ""
    echo "Testing executable..."
    if [ -f "dist/ssl-tester" ]; then
        ./dist/ssl-tester --help
    elif [ -f "dist/ssl-tester.exe" ]; then
        ./dist/ssl-tester.exe --help
    fi
    
    echo ""
    echo "Executable is ready in dist/"
else
    echo ""
    echo "ERROR: Build failed - executable not found"
    exit 1
fi


