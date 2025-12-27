#!/bin/bash
# OpenPLC Runtime - MSYS2 Provisioning Script
# This script is run inside MSYS2 to install all required packages and dependencies
# for the OpenPLC Runtime Windows distribution.

set -e

echo "=========================================="
echo "OpenPLC Runtime - MSYS2 Provisioning"
echo "=========================================="

# Update package database and upgrade existing packages
echo "[1/6] Updating MSYS2 package database..."
pacman -Syu --noconfirm

# Install required packages
echo "[2/6] Installing required packages..."
pacman -S --noconfirm --needed \
    base-devel \
    gcc \
    make \
    cmake \
    pkg-config \
    python \
    python-pip \
    python-setuptools \
    git \
    sqlite3

# Verify installations
echo "[3/6] Verifying installations..."
echo "GCC version: $(gcc --version | head -n1)"
echo "Python version: $(python3 --version)"
echo "CMake version: $(cmake --version | head -n1)"

# Get the OpenPLC directory (parent of windows folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENPLC_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$OPENPLC_DIR/venvs/runtime"

echo "[4/6] Setting up Python virtual environment..."
cd "$OPENPLC_DIR"

# Create virtual environment
python3 -m venv "$VENV_DIR"

# Upgrade pip and install dependencies
"$VENV_DIR/bin/python3" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python3" -m pip install -r "$OPENPLC_DIR/requirements.txt"
"$VENV_DIR/bin/python3" -m pip install -e .

echo "[5/6] Building OpenPLC Runtime..."
# Create build directory
mkdir -p "$OPENPLC_DIR/build"
cd "$OPENPLC_DIR/build"

# Run CMake and build
cmake ..
make -j$(nproc)

cd "$OPENPLC_DIR"

echo "[6/6] Cleaning up to reduce size..."
# Clean pacman cache
pacman -Scc --noconfirm

# Remove unnecessary files
rm -rf /var/cache/pacman/pkg/*
rm -rf /var/log/*
rm -rf /tmp/*

# Create installation marker
echo "Installation completed at $(date)" > "$OPENPLC_DIR/.installed"

echo "=========================================="
echo "OpenPLC Runtime provisioning complete!"
echo "=========================================="
