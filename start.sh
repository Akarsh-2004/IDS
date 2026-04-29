#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQ_FILE="$ROOT_DIR/backend/requirements.txt"

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "Python is not installed or not in PATH."
  exit 1
fi

if [[ ! -f "$REQ_FILE" ]]; then
  echo "Missing dependency file: $REQ_FILE"
  exit 1
fi

echo "[1/4] Creating virtual environment (if needed)..."
if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

if [[ -f "$VENV_DIR/Scripts/activate" ]]; then
  # Windows (Git Bash)
  # shellcheck disable=SC1091
  source "$VENV_DIR/Scripts/activate"
else
  # Linux/macOS
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
fi

echo "[2/4] Installing backend dependencies..."
python -m pip install --upgrade pip wheel setuptools
python -m pip install -r "$REQ_FILE"

echo "[3/4] Starting backend at http://127.0.0.1:8000 ..."
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir "$ROOT_DIR/backend" &
BACKEND_PID=$!

echo "[4/4] Starting frontend at http://127.0.0.1:3000 ..."
python -m http.server 3000 --directory "$ROOT_DIR/frontend" &
FRONTEND_PID=$!

cleanup() {
  echo ""
  echo "Stopping services..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "Pipeline is running."
echo "Frontend: http://127.0.0.1:3000"
echo "Backend:  http://127.0.0.1:8000"
echo "Real-time IDS: use UI controls or POST /realtime/start"
echo "Note: Live NIC mode may require elevated privileges."
echo "Press Ctrl+C to stop."

wait
