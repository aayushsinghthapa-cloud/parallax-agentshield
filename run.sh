#!/usr/bin/env bash
# One command: backend on :8000, frontend on :5173. Ctrl-C stops both.
# First run creates backend/.venv and frontend/node_modules (project-local, nothing global).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example (replay mode needs no keys)."; fi

PY="${PYTHON:-python3}"
if [ ! -x backend/.venv/bin/python ]; then
  echo "Creating backend/.venv ..."
  "$PY" -m venv backend/.venv
  backend/.venv/bin/pip install -q --upgrade pip
  backend/.venv/bin/pip install -q -r backend/requirements.txt
fi
if [ ! -d frontend/node_modules ]; then
  echo "Installing frontend packages ..."
  (cd frontend && npm install --no-audit --no-fund)
fi

backend/.venv/bin/uvicorn backend.server:app --host 127.0.0.1 --port 8000 &
BACK=$!
(cd frontend && npm run dev) &
FRONT=$!
trap 'kill $BACK $FRONT 2>/dev/null || true' EXIT INT TERM

echo
echo "  LEASH  →  http://localhost:5173   (API on http://127.0.0.1:8000)"
echo
wait
