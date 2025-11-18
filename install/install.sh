#!/usr/bin/env bash
set -euo pipefail

### --- OS CHECK --- ###
if [[ $OSTYPE != linux-gnu* ]]; then
  echo "[ERROR] This script supports Linux only. Aborting."
  exit 1
fi

# --- Auto-save if running from a pipe ---
if [ -p /dev/stdin ]; then
    TMP_SCRIPT="/tmp/install-openplc-runtime.sh"
    echo "[INFO] Detected script running from a pipe. Saving to $TMP_SCRIPT..."
    cat > "$TMP_SCRIPT"
    chmod +x "$TMP_SCRIPT"

    echo "[INFO] Re-running saved script..."
    exec "$TMP_SCRIPT" "$@"
fi

### --- CONFIGURATION --- ###
IMAGE_NAME="ghcr.io/autonomy-logic/openplc-runtime:latest"
CONTAINER_NAME="openplc-runtime"
CONTAINER_PORT="8443"
HOST_PORT="8443"

# Check for root privileges
check_root()
{
    if [[ $EUID -ne 0 ]]; then
        echo "[INFO] Root privileges are required. Trying to elevate with sudo..."
        # Re-run the script with sudo, passing all original arguments
        exec sudo "$0" "$@"
        # exec replaces the current shell with the new command, so the rest of the script continues as root
    fi
}

# Make sure we are root before proceeding
check_root "$@"

### --- DEPENDENCIES --- ###
echo "Checking and installing required dependencies..."
PKG_MANAGER=""

# Detect package manager
if command -v apt-get &>/dev/null; then
  PKG_MANAGER="apt-get"
elif command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
  PKG_MANAGER="yum"
else
  echo "[ERROR] No supported package manager found (apt, dnf, or yum). Install dependencies manually."
  exit 1
fi

# Define package names per package manager
declare -A PKG_MAP
if [[ "$PKG_MANAGER" == "apt-get" ]]; then
  PKG_MAP=(
    [docker]="docker.io"
  )
elif [[ "$PKG_MANAGER" == "dnf" ]]; then
  PKG_MAP=(
    [docker]="docker"
  )
elif [[ "$PKG_MANAGER" == "yum" ]]; then
  PKG_MAP=(
    [docker]="docker"
  )
fi

# Collect missing packages
MISSING_PKGS=()
for cmd in docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Missing dependency: $cmd"
    MISSING_PKGS+=("${PKG_MAP[$cmd]}")
  else
    echo "[SUCCESS] $cmd is already installed."
  fi
done

# Install missing packages
if [ ${#MISSING_PKGS[@]} -ne 0 ]; then
  echo "Updating package lists and installing missing dependencies: ${MISSING_PKGS[*]}"
  case "$PKG_MANAGER" in
    apt-get)
      sudo apt-get update -y
      sudo apt-get install -y "${MISSING_PKGS[@]}"
      ;;
    dnf)
      sudo dnf install -y "${MISSING_PKGS[@]}"
      ;;
    yum)
      sudo yum install -y "${MISSING_PKGS[@]}"
      ;;
  esac
fi

echo "Attempting to pull Docker image: $IMAGE_NAME"
if docker pull "$IMAGE_NAME" 2>/dev/null; then
    echo "[SUCCESS] Image pulled successfully from registry."
else
    echo "[INFO] Image not available in registry. Building locally..."

    if [ ! -f "Dockerfile" ]; then
        echo "[ERROR] Dockerfile not found. Please run this script from the openplc-runtime repository root."
        echo "Or clone the repository first:"
        echo "  git clone https://github.com/Autonomy-Logic/openplc-runtime.git"
        echo "  cd openplc-runtime"
        echo "  sudo ./install/install.sh"
        exit 1
    fi

    echo "Building Docker image locally..."
    docker build -t "$IMAGE_NAME" .
    echo "[SUCCESS] Image built successfully."
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Existing container detected. Stopping and removing..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

echo "Creating and starting container: $CONTAINER_NAME"
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${HOST_PORT}:${CONTAINER_PORT}" \
    "$IMAGE_NAME"

echo "[SUCCESS] Container started successfully."

# Detect color support
if [ -t 1 ] && command -v tput >/dev/null && [ "$(tput colors 2>/dev/null)" -ge 8 ]; then
  GREEN="$(tput setaf 2)"
  CYAN="$(tput setaf 6)"
  YELLOW="$(tput setaf 3)"
  GRAY="$(tput setaf 8)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  GREEN=""
  CYAN=""
  YELLOW=""
  GRAY=""
  BOLD=""
  RESET=""
fi

echo
echo
echo -e "${BOLD}${GREEN}INSTALLATION COMPLETE${RESET}"
echo -e "${GRAY}=====================================================${RESET}"
echo
echo -e "OpenPLC Runtime is now running in a Docker container."
echo -e "Access the web interface at: ${BOLD}${CYAN}https://localhost:${HOST_PORT}${RESET}"
echo
echo -e "Container name: ${YELLOW}${CONTAINER_NAME}${RESET}"
echo
echo "Useful commands:"
echo "  View logs:    docker logs $CONTAINER_NAME"
echo "  Stop:         docker stop $CONTAINER_NAME"
echo "  Start:        docker start $CONTAINER_NAME"
echo "  Remove:       docker rm -f $CONTAINER_NAME"
echo -e "${GRAY}=====================================================${RESET}"
