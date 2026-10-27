# AgentWatch — Complete Setup and Run Guide

AgentWatch is a local prototype of a security gateway for AI-agent tool calls. The gateway checks proposed actions before they reach simulated protected tools, records decisions, scans tool output for possible prompt injection, and demonstrates selective restrictions.

> **Important:** This is a development/demo prototype, not production security software. Read [Known limitations](#known-limitations) before using it for anything beyond a local demonstration.

## 1. What you need

### Required

- **Python 3.11 or newer**
- The AgentWatch ZIP archive
- A terminal: PowerShell or Command Prompt on Windows; Terminal on macOS/Linux

### Optional

- **Node.js and npm** only if you want to work on or rebuild the frontend
- An OpenAI API key only if you want to try the optional LLM evidence/alignment layer
- PostgreSQL only if you want to experiment with the optional PostgreSQL configuration; it has not been verified in this build

Check Python:

**Windows**

```powershell
py --version
```

**macOS/Linux**

```bash
python3 --version
```

If Python is older than 3.11, install a current Python 3 release and reopen your terminal.

## 2. Download and extract

1. Download `AgentWatch-Repaired.zip` from the ChatGPT attachment.
2. Extract the ZIP using File Explorer, Finder, or your archive utility.
3. Open a terminal **inside the extracted `agentwatch` folder**. This folder should contain `run.sh`, `run.bat`, `requirements.txt`, `backend/`, and `frontend/`.

Do not run the commands below from inside `backend/` or `frontend/` unless a step explicitly tells you to.

## 3. Start AgentWatch — easiest method

### Windows

Open PowerShell or Command Prompt in the `agentwatch` folder and run:

```bat
run.bat
```

The script creates a local `.venv` if needed, installs backend dependencies when `requirements.txt` changes, and starts the API server.

If Windows blocks the script or it fails, use the manual method in section 4.

### macOS/Linux

Open Terminal in the `agentwatch` folder and run:

```bash
chmod +x run.sh
./run.sh
```

The script creates a local virtual environment if needed, installs backend dependencies when `requirements.txt` changes, and starts the API server.

### Open the app

When the server is running, open:

- Dashboard: <http://127.0.0.1:8000>
- Health endpoint: <http://127.0.0.1:8000/health>
- API docs: <http://127.0.0.1:8000/docs>

Keep the terminal open while using the app. To stop the server, press **Ctrl+C** in that terminal.

The first startup seeds demo records. The server is configured for local use on `127.0.0.1`; it is not intended to be exposed directly to the internet.

## 4. Manual setup and run

Use this method if the run script does not work or if you prefer to see each step.

### Windows PowerShell

From the `agentwatch` folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

If PowerShell refuses to activate the environment, you can use Command Prompt instead:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

### macOS/Linux

From the `agentwatch` folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

If `python3` is not found, install Python 3.11+ first. If port 8000 is already in use, stop the other process or change the port in the final `uvicorn` command, then use that port in the browser URL.

## 5. Demo credentials and authentication

In the default local demo configuration, the seeded demo credentials are:

- **Reviewer/admin token:** `aw_admin_demo_token`
- **Demo agent token:** `aw_demo_token`
- **Seeded task:** `task-demo`

The gateway expects the agent token as a Bearer token. Admin/reviewer API routes expect the `X-Admin-Token` header. An agent token should not be used for admin routes.

These credentials are intentionally predictable for a local demo. **Do not use them on a public server or with real data.** For a non-demo setup, configure `AGENTWATCH_DEMO=0`, provide a strong `AGENTWATCH_SECRET`, and set a strong `AGENTWATCH_ADMIN_TOKEN` before starting the backend. Protect the terminal output and environment variables.

The shipped UI includes a reviewer-token prompt/login area. If the dashboard asks for a reviewer token in demo mode, enter `aw_admin_demo_token`.

## 6. Verify that the server works

With the server running, open <http://127.0.0.1:8000/health>. It should return a small JSON health response.

You can also test from another terminal.

### Health check

```bash
curl http://127.0.0.1:8000/health
```

### Reviewer/admin API check

```bash
curl -H "X-Admin-Token: aw_admin_demo_token" http://127.0.0.1:8000/api/overview
```

### Sample agent gateway call

```bash
curl -X POST http://127.0.0.1:8000/gateway/call \
  -H "Authorization: Bearer aw_demo_token" \
  -H "Content-Type: application/json" \
  -d '{"tool":"document.read","params":{"resource_id":"Quote-A"},"task_id":"task-demo","session_id":"manual-demo"}'
```

On Windows Command Prompt, use this single-line command if multiline quoting is inconvenient:

```bat
curl -X POST http://127.0.0.1:8000/gateway/call -H "Authorization: Bearer aw_demo_token" -H "Content-Type: application/json" -d "{\"tool\":\"document.read\",\"params\":{\"resource_id\":\"Quote-A\"},\"task_id\":\"task-demo\",\"session_id\":\"manual-demo\"}"
```

The exact decision depends on the seeded state and policy checks. A gateway response should include the decision and audit evidence; do not interpret a successful HTTP response alone as an ALLOW decision.

## 7. Run the automated tests

Tests use a temporary test database fixture; they are intended not to modify the demo database.

### Install test dependencies

Activate the virtual environment first, then run from the `agentwatch` folder:

**Windows**

```powershell
python -m pip install -r requirements-dev.txt
```

**macOS/Linux**

```bash
python -m pip install -r requirements-dev.txt
```

### Run pytest

```bash
python -m pytest backend/tests -q
```

To run one test module:

```bash
python -m pytest backend/tests/test_gateway.py -q
```

For a more verbose test report:

```bash
python -m pytest backend/tests -v
```

## 8. Run the scenario suite

Run these commands from the `agentwatch` folder with the virtual environment activated.

```bash
python -m backend.app.scenarios
```

The scenario suite covers the procurement workflow, forbidden HR access, indirect prompt injection, role versions, cold-start behavior, delegation, cross-session risk, alternative vendors, alert explanation, selective containment, approval binding, and recovery demonstrations.

Helper scripts are also included:

- macOS/Linux: `bash scripts/test.sh`
- macOS/Linux: `bash scripts/scenarios.sh`
- Windows: `scripts\test.bat`
- Windows: `scripts\scenarios.bat`

Scenario results are local simulation results only, not external benchmark measurements.

## 9. Optional OpenAI integration

The default detection path is deterministic and does not require an API key. The optional LLM module requires the OpenAI Python SDK and an environment variable.

1. Obtain an API key from your OpenAI account if you choose to use this optional feature.
2. Install the optional dependency from the `agentwatch` folder:

   ```bash
   python -m pip install -r optional-requirements.txt
   ```

3. Set the key in the same terminal before starting the server.

   **Windows PowerShell**

   ```powershell
   $env:OPENAI_API_KEY = "your-key-here"
   ```

   **Windows Command Prompt**

   ```bat
   set OPENAI_API_KEY=your-key-here
   ```

   **macOS/Linux**

   ```bash
   export OPENAI_API_KEY="your-key-here"
   ```

4. Start or restart AgentWatch from that terminal.

Never commit a real API key into source control, screenshots, or the ZIP. Do not paste it into a public issue. If the optional LLM is unavailable, the intended behavior is to continue with deterministic checks. The full LLM-driven simulated-agent mode is not implemented in this build.

## 10. Frontend development (optional)

The shipped `frontend/dist` is a static dashboard bundle. The React/Vite source is under `frontend/src`, but this repair archive's shipped bundle has **not** been verified as a build of that source. Treat frontend rebuild as development work, not a prerequisite for running the shipped app.

If Node.js 20+ and npm are installed, from the `agentwatch` folder:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server is configured for `127.0.0.1:5173`. Run the backend separately on port 8000. To attempt a production rebuild:

```bash
npm run build
```

A committed, verified `package-lock.json` is not included, so `npm ci` is not the correct install command for this archive. Package registry access and a successful production build were not verified during preparation.

## 11. Configuration

The project includes `.env.example` as a reference. The application does not automatically load a `.env` file unless a dotenv loader is added; export the variables in your shell or configure them in your process manager.

Common variables include:

- `DATABASE_URL` — database connection URL; SQLite is the default path for local use.
- `AGENTWATCH_DEMO` — set to `1` for the predictable local demo setup; set to `0` for non-demo mode.
- `AGENTWATCH_ADMIN_TOKEN` — reviewer/admin credential.
- `AGENTWATCH_SECRET` — server secret used for token hashing/signing-related behavior.
- `HALF_LIFE_HOURS` — time-decay half-life for cumulative risk.
- `RISK_HOLD_THRESHOLD` and `RISK_QUARANTINE_THRESHOLD` — cumulative risk thresholds.
- `ALLOWED_EMAIL_DOMAINS` — configured email destination allowlist.
- `OPENAI_API_KEY` — optional LLM integration.

Restart the backend after changing environment variables. PostgreSQL and Docker Compose are included as optional examples but have not been validated in this build.

## 12. Troubleshooting

### The dashboard does not open

- Confirm the backend terminal is still running.
- Visit <http://127.0.0.1:8000/health> first.
- Confirm you are using port 8000, or the custom port you selected.
- Check the terminal for Python import or dependency errors.

### `python` is not recognized

- Windows: try `py -3` and use the Windows commands above.
- macOS/Linux: use `python3` to create the virtual environment, then activate it and use `python` inside the environment.

### Dependency installation fails

- Check your internet connection and retry `python -m pip install -r requirements.txt`.
- Confirm Python is 3.11 or newer.
- If your network uses a proxy or blocks package registries, install dependencies on an allowed network before running the app.

### Port 8000 is occupied

Run the server on another port, for example:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001
```

Then open <http://127.0.0.1:8001>.

### Admin requests return 401/403

Use the reviewer token in `X-Admin-Token`; do not send the agent token to admin routes. In the default demo configuration, the reviewer token is `aw_admin_demo_token`.

### A gateway call is denied

A 200 HTTP response can still contain a DENY/HOLD decision. Inspect the returned decision, checks, and reasons. The gateway is designed to reject out-of-task actions even when an agent token is valid.

## 13. Known limitations

- This is a local demonstration prototype and is not production-ready.
- The database uses a generic JSON records table rather than the fully normalized SQLAlchemy schema requested in the original specification.
- Cross-process database locking and production-grade atomic concurrency protection are not implemented.
- The shipped static dashboard is not verified as a build of the included React source; several requested UI workflows remain incomplete.
- The complete recovery state machine, fully human-verified baseline workflow, and some reviewer workflows are demonstration-level.
- PostgreSQL, Docker Compose, Windows runtime behavior, and the frontend production build were not verified in this build environment.
- The default demo tokens are predictable and must never be used on an internet-facing deployment or with real credentials/data.
- The evaluation uses local scenarios and is not an external security benchmark.

## 14. Project structure

```text
agentwatch/
├── backend/
│   ├── app/                 # FastAPI app, gateway, policy checks, tools, scenarios
│   └── tests/               # pytest suite
├── frontend/
│   ├── src/                 # React/Vite source
│   └── dist/                # Shipped static dashboard bundle
├── scripts/                 # Test, scenario and build helper scripts
├── requirements.txt         # Backend dependencies
├── requirements-dev.txt     # Test/development dependencies
├── optional-requirements.txt# Optional OpenAI SDK
├── run.sh                   # macOS/Linux startup
├── run.bat                  # Windows startup
└── README.md                # Project guide
```

## 15. Three-minute demo flow

1. **Normal operation:** run the normal procurement scenario and show supplier quote reads and purchase-request preparation without submission.
2. **Indirect prompt injection:** run the malicious Quote-B scenario; inspect the taint evidence, denied HR-Salary read, and email restriction.
3. **Selective containment:** show that approved supplier-document reads can continue while risky tools are restricted.
4. **Approval binding:** approve one exact action, then change one argument and show that the approval does not cover the changed request.
5. **Review and evaluation:** open the alert explanation and show the measured local scenario metrics. State clearly that these are local simulation results, not external benchmark results.

---

**Local-only reminder:** keep the server bound to `127.0.0.1`, use demo credentials only for demos, and do not put real supplier, employee, or confidential business data into this prototype.
