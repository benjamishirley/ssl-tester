# Executable Build Guide

This document describes how to create a standalone executable of the ssl-tester tool.

## Prerequisites

- Python 3.11 or higher
- pip

## Quick Start

### macOS/Linux

```bash
# Run build script
./build-executable.sh
```

The script:
1. Automatically creates a venv (if not present)
2. Installs all dependencies
3. Builds the executable with PyInstaller
4. Tests the executable

### Windows

```cmd
# Run build script
build-executable.bat
```

## Manual Build Steps

If you want to perform the build process manually:

```bash
# 1. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# or: venv\Scripts\activate  # Windows

# 2. Install dependencies
pip install -e ".[build]"

# 3. Build with PyInstaller
pyinstaller ssl-tester.spec

# Or directly with PyInstaller (without spec file):
pyinstaller --onefile --name ssl-tester \
    --hidden-import=ssl_tester \
    --hidden-import=cryptography \
    --collect-all=cryptography \
    --collect-all=certifi \
    --console \
    src/ssl_tester/cli.py
```

## Result

After successful build, you'll find the executable in:
- `dist/ssl-tester` (macOS/Linux)
- `dist/ssl-tester.exe` (Windows)

## Using the Executable

The executable can be used directly without Python installation:

```bash
# macOS/Linux
./dist/ssl-tester example.com

# Windows
dist\ssl-tester.exe example.com
```

## Important Notes

1. **Size**: The executable is relatively large (~20-50 MB), as all dependencies (including cryptography) are bundled.

2. **OpenSSL**: The executable requires OpenSSL on the target system (usually already installed).

3. **CA Certificates**: System CA certificates are still used. `certifi` is bundled as fallback.

4. **Cross-Platform**: The executable must be built on the target platform (no cross-compiling).

## Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"

Solution: Make sure `--collect-all=cryptography` is used.

### "Failed to execute script"

Solution: 
- Check if all hidden-imports are correct
- Use `--debug=all` for detailed error messages

### Executable is too large

Solution:
- Use `--exclude-module` for unneeded modules
- Check if `--onefile` is really needed (alternative: `--onedir`)

## Alternative: Wheel Package

If you want to create a Python package (Wheel):

```bash
pip install build
python -m build
```

Result: `dist/ssl_tester-0.1.0-py3-none-any.whl`

