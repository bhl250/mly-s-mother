#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-"$PROJECT_ROOT/bin"}"
ENV_FILE="$PROJECT_ROOT/env.sh"
PROFILE_D_FILE="/etc/profile.d/processdata-tools.sh"

mkdir -p "$BIN_DIR"

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "This command needs root privileges and sudo is not available: $*" >&2
    exit 1
  fi
}

install_apt_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer currently supports Debian/Ubuntu systems with apt-get." >&2
    exit 1
  fi

  run_root apt-get update
  run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3-venv \
    python3-pip \
    tshark \
    wireshark-common \
    libpcap-dev
}

link_tool() {
  local tool="$1"
  local tool_path
  tool_path="$(command -v "$tool" || true)"
  if [ -z "$tool_path" ]; then
    echo "Missing command after install: $tool" >&2
    exit 1
  fi
  ln -sfn "$tool_path" "$BIN_DIR/$tool"
}

install_profile_path() {
  cat > "$ENV_FILE" <<EOF
#!/usr/bin/env bash
export PATH="$BIN_DIR:\$PATH"
EOF
  chmod +x "$ENV_FILE"

  if [ "${REGISTER_SYSTEM_PATH:-1}" = "1" ]; then
    run_root sh -c "printf '%s\n' '# processdata external tools' 'export PATH=\"$BIN_DIR:\$PATH\"' > '$PROFILE_D_FILE'"
    echo "Registered project bin in system profile: $PROFILE_D_FILE"
    echo "For the current shell, run: source $ENV_FILE"
  else
    echo "Skipped system PATH registration. For this shell, run: source $ENV_FILE"
  fi
}

install_apt_packages

link_tool editcap
link_tool tshark
link_tool mergecap

install_profile_path

echo "External command dependencies are ready in: $BIN_DIR"
editcap --version | head -n 1 || true
tshark --version | head -n 1 || true
mergecap --version | head -n 1 || true
