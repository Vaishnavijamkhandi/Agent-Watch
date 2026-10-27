#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "$PYTHON_BIN" ]]; then echo "Python 3.11+ is required." >&2; exit 1; fi
if [[ ! -d .venv ]]; then "$PYTHON_BIN" -m venv .venv; fi
source .venv/bin/activate
REQ_HASH="$(python -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("requirements.txt").read_bytes()).hexdigest())')"
if [[ ! -f .venv/.requirements.sha256 ]] || [[ "$REQ_HASH" != "$(cat .venv/.requirements.sha256)" ]]; then
  python -m pip install -r requirements.txt
  printf "%s" "$REQ_HASH" > .venv/.requirements.sha256
fi
export AGENTWATCH_DEMO="${AGENTWATCH_DEMO:-1}"
echo "AgentWatch dashboard: http://127.0.0.1:8000"
echo "Reviewer token is printed by the backend on startup (demo default: aw_admin_demo_token)."
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
