#!/bin/bash
# SHADOWCORE Environment Setup
# Sets up all dependencies and clones reference repositories

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="${PROJECT_DIR}/deps"

echo "=== SHADOWCORE Environment Setup ==="
echo "Project directory: ${PROJECT_DIR}"
echo ""

# --- System packages ---
echo "--- Installing system packages ---"
if command -v apt-get &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y \
        pciutils \
        binwalk \
        build-essential \
        cmake \
        python3-dev \
        python3-venv \
        linux-headers-"$(uname -r)" \
        git
elif command -v dnf &>/dev/null; then
    sudo dnf install -y \
        pciutils \
        binwalk \
        gcc gcc-c++ make \
        cmake \
        python3-devel \
        kernel-headers \
        git
else
    echo "Warning: Unknown package manager. Install manually:"
    echo "  pciutils, binwalk, cmake, python3-dev, linux-headers"
fi

# --- Python virtual environment ---
echo ""
echo "--- Setting up Python environment ---"
cd "$PROJECT_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "Python venv ready at ${PROJECT_DIR}/.venv"

# --- Clone reference repositories ---
echo ""
echo "--- Cloning reference repositories ---"
mkdir -p "$DEPS_DIR"

# NVIDIA open-source kernel modules
if [ ! -d "${DEPS_DIR}/open-gpu-kernel-modules" ]; then
    echo "Cloning NVIDIA open-source kernel modules..."
    git clone --depth 1 https://github.com/NVIDIA/open-gpu-kernel-modules \
        "${DEPS_DIR}/open-gpu-kernel-modules"
else
    echo "NVIDIA open-source kernel modules already cloned"
fi

# envytools
if [ ! -d "${DEPS_DIR}/envytools" ]; then
    echo "Cloning envytools..."
    git clone --depth 1 https://github.com/envytools/envytools \
        "${DEPS_DIR}/envytools"
    echo "Building envytools..."
    cd "${DEPS_DIR}/envytools"
    cmake . && make -j"$(nproc)" || echo "Warning: envytools build failed (may need additional deps)"
    cd "$PROJECT_DIR"
else
    echo "envytools already cloned"
fi

# --- Verify GPU ---
echo ""
echo "--- GPU Detection ---"
if command -v lspci &>/dev/null; then
    echo "NVIDIA GPUs found:"
    lspci | grep -i nvidia || echo "  No NVIDIA GPUs detected"
else
    echo "lspci not available — install pciutils"
fi

# --- Summary ---
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Activate venv:  source .venv/bin/activate"
echo "  2. Run firmware scan:  python tools/firmware-extract/extract_gsp_firmware.py --scan-system"
echo "  3. Map GPU BARs:  sudo python tools/bar-mapper/map_gpu_bars.py --probe"
echo "  4. Catalog RPC:  python tools/gsp-rpc-monitor/gsp_rpc_catalog.py deps/open-gpu-kernel-modules"
echo "  5. Test persistence:  sudo python tools/vram-persistence/test_vram_persistence.py write --bdf <BDF>"
