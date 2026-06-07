#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-"$PROJECT_ROOT/runs"}"
NAME="processdata"
USE_PROJECT_ENV=1

usage() {
  cat <<EOF
Usage:
  bash scripts/run_detached.sh [--name NAME] [--no-project-env] -- COMMAND [ARGS...]

Examples:
  bash scripts/run_detached.sh --name pretrain -- \\
    python data_process/dataset_generation.py pretrain --pcap-path /data/raw --force

  bash scripts/run_detached.sh --name finetune_generate -- \\
    python data_process/main.py --pcap-path /data/raw/splitcap

Options:
  --name NAME        Run name used for log and pid files. Default: processdata
  --no-project-env  Do not source env.sh or activate_project_env.sh before running COMMAND
  -h, --help        Show this help

Outputs:
  runs/NAME.pid
  runs/NAME.out.log
  runs/NAME.err.log
  runs/NAME.command.sh
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      NAME="${2:?--name requires a value}"
      shift 2
      ;;
    --no-project-env)
      USE_PROJECT_ENV=0
      shift
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option before --: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ "$#" -eq 0 ]; then
  echo "Missing COMMAND. Put the command after --." >&2
  usage >&2
  exit 1
fi

mkdir -p "$RUN_DIR"

PID_FILE="$RUN_DIR/$NAME.pid"
OUT_LOG="$RUN_DIR/$NAME.out.log"
ERR_LOG="$RUN_DIR/$NAME.err.log"
COMMAND_FILE="$RUN_DIR/$NAME.command.sh"

if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "A run named '$NAME' is already active with PID $OLD_PID." >&2
    echo "Use a different --name or stop it first: kill $OLD_PID" >&2
    exit 1
  fi
fi

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"$PROJECT_ROOT\""
  if [ "$USE_PROJECT_ENV" = "1" ]; then
    echo "[ -f \"$PROJECT_ROOT/env.sh\" ] && source \"$PROJECT_ROOT/env.sh\""
    echo "[ -f \"$PROJECT_ROOT/activate_project_env.sh\" ] && source \"$PROJECT_ROOT/activate_project_env.sh\""
  fi
  printf 'exec'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
} > "$COMMAND_FILE"
chmod +x "$COMMAND_FILE"

nohup bash "$COMMAND_FILE" > "$OUT_LOG" 2> "$ERR_LOG" < /dev/null &
PID="$!"
echo "$PID" > "$PID_FILE"

echo "Started detached run: $NAME"
echo "PID: $PID"
echo "Command file: $COMMAND_FILE"
echo "stdout log: $OUT_LOG"
echo "stderr log: $ERR_LOG"
echo
echo "Check status:"
echo "  kill -0 $PID && echo running || echo stopped"
echo
echo "Follow logs:"
echo "  tail -f $OUT_LOG"
echo "  tail -f $ERR_LOG"
