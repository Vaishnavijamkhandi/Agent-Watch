@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
if not exist .venv %PY% -m venv .venv
call .venv\Scripts\activate.bat
if errorlevel 1 exit /b 1
python -c "import hashlib,pathlib,sys; p=pathlib.Path('requirements.txt'); f=pathlib.Path('.venv/.requirements.sha256'); sys.exit(0 if f.exists() and f.read_text().strip()==hashlib.sha256(p.read_bytes()).hexdigest() else 1"
if errorlevel 1 (
  python -m pip install -r requirements.txt || exit /b 1
  python -c "import hashlib,pathlib; pathlib.Path('.venv/.requirements.sha256').write_text(hashlib.sha256(pathlib.Path('requirements.txt').read_bytes()).hexdigest())"
)
if not defined AGENTWATCH_DEMO set AGENTWATCH_DEMO=1
echo AgentWatch dashboard: http://127.0.0.1:8000
echo Demo reviewer token: aw_admin_demo_token (non-demo token is printed by backend)
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
