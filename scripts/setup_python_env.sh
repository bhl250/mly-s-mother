#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-"$PROJECT_ROOT/.venv"}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install -r "$PROJECT_ROOT/requirements.txt"

if [ "${INSTALL_OPTIONAL_PCAP_SPLITTER:-1}" = "1" ]; then
  if ! "$VENV_DIR/bin/python" -m pip install -r "$PROJECT_ROOT/requirements-optional.txt"; then
    echo "WARNING: optional pcap-splitter install failed; Scapy fallback splitting remains available." >&2
  fi
fi

cat > "$PROJECT_ROOT/activate_project_env.sh" <<EOF
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
export PATH="$PROJECT_ROOT/bin:\$PATH"
EOF
chmod +x "$PROJECT_ROOT/activate_project_env.sh"

echo "Python environment ready: $VENV_DIR"
echo "Activate it with: source $PROJECT_ROOT/activate_project_env.sh"
