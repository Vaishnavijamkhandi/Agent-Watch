# AgentWatch — Security Gateway Prototype (repair build)

AgentWatch is a local procurement-agent security gateway prototype. It demonstrates that valid credentials do not imply task relevance: the gateway checks a proposed tool call before it reaches a mock executor, records a decision, and can selectively restrict risky tools after suspected indirect prompt injection.

> **Prototype, not production security software.** Read the limitations section before using it beyond a local demonstration.

## Architecture

```text
 ProcurementAgent (agent token; no tool credentials)
                 |
                 v
 +----------------------------------------------+
 | AgentWatch FastAPI gateway                   |
 | Identity -> State/restrictions -> Role        |
 | -> Trusted classification -> Task relevance  |
 | -> Behavior/taint -> Approval -> Cold start  |
 | -> Delegation -> Decision / audit event      |
 +----------------------------------------------+
                 |
                 v
 +----------------------------------------------+
 | Trusted mock executors                       |
 | Document Store | Supplier Portal | Email Outbox|
 +----------------------------------------------+
```

The shipped prototype uses a SQLAlchemy `records` table containing JSON records rather than the fully normalized SQLAlchemy domain schema requested in the repair brief. It is SQLite-first. `DATABASE_URL` can point at PostgreSQL after installing `optional-postgres-requirements.txt`, but PostgreSQL has not been verified in this build.

## Prerequisites and quick start

- Python 3.11+
- Node.js 20+ and npm only if rebuilding the frontend

### Windows

1. Extract the ZIP and open PowerShell or Command Prompt in `agentwatch/`.
2. Run `run.bat`.
3. Open <http://127.0.0.1:8000>.

### macOS / Linux

1. Extract the ZIP and open a terminal in `agentwatch/`.
2. Run `chmod +x run.sh && ./run.sh`.
3. Open <http://127.0.0.1:8000>.

The first run creates a virtual environment and installs the backend requirements. The local demo is enabled by default and prints its reviewer and demo-agent tokens to the terminal. In demo mode the tokens are intentionally predictable and are **not suitable for deployment**. For a non-demo setup, set `AGENTWATCH_DEMO=0`, set a long random `AGENTWATCH_SECRET`, and set `AGENTWATCH_ADMIN_TOKEN` before startup. Protect the printed token.

The seeded demo agent token is `aw_demo_token`; its task is `task-demo`. The demo reviewer token is `aw_admin_demo_token`. Admin/reviewer routes require `X-Admin-Token`; `/gateway/call` requires a bearer agent token. These demo credentials are only acceptable for an isolated local demo.

## Manual API check

```bash
curl http://127.0.0.1:8000/health
curl -H 'X-Admin-Token: aw_admin_demo_token' http://127.0.0.1:8000/api/overview
curl -X POST http://127.0.0.1:8000/gateway/call \
  -H 'Authorization: Bearer aw_demo_token' -H 'Content-Type: application/json' \
  -d '{"tool":"document.read","params":{"resource_id":"Quote-A"},"task_id":"task-demo","session_id":"manual-demo"}'
```

## Test and scenario commands

```bash
python -m pip install -r requirements-dev.txt
python -m pytest backend/tests -q
python -m backend.app.scenarios  # from inside agentwatch/
# or, from the parent directory: python -m agentwatch.scenarios
```

Helper scripts are available in `scripts/test.sh`, `scripts/scenarios.sh`, `scripts/build_frontend.sh` and their `.bat` equivalents.

## Nine check pipeline

1. Identity/authentication.
2. Agent state and matching tool restrictions.
3. Current approved role version and tool permission.
4. Trusted server-side resource classification.
5. Task scope and forbidden-action relevance.
6. Behavior context and recent taint markers.
7. Exact-argument approval binding.
8. Cold-start conservative handling.
9. Delegation scope.

A denied or held call is recorded as an event and does not reach the protected executor. Tool execution failures are converted into denial records. The implementation remains a prototype: not every check is fully factored into a production-grade policy engine, and the generic JSON store is not a normalized event database.

## Decision table

| Decision | Meaning |
|---|---|
| ALLOW | The deterministic policy checks permit this call. |
| HOLD | Exact human approval or reviewer clarification is required. |
| DENY | A policy or scope rule rejects the action. |
| QUARANTINE | Repeated/high cumulative risk causes agent quarantine. |

Risk contribution is stored per event; ALLOW and HOLD contribute zero, while DENY contributes according to a small deterministic severity scheme. Recent contributions decay exponentially using `HALF_LIFE_HOURS`. Thresholds are configurable using `RISK_HOLD_THRESHOLD` and `RISK_QUARANTINE_THRESHOLD`.

## Scenario coverage

- **Normal operation:** compare supplier quotes and prepare (not submit) a purchase request.
- **Direct HR read:** sensitive classification is denied before tool execution.
- **Indirect injection:** Quote-B is scanned, matched spans are sanitized, taint is marked, and high-risk tools are restricted. Attribution is worded as possible influence, not proven authorship.
- **Role change:** pending and approved role-version records can be created through the API.
- **Cold start:** out-of-scope non-trivial actions are conservative; exact approval is bound to arguments for one call.
- **Delegation:** child agent registration validates the delegated tools/resources against the parent role/task.
- **Slow evasion:** cross-session denial contributions can escalate to HOLD/QUARANTINE.
- **Alternative vendor:** resource scope and trusted vendor status are checked.
- **Alert explanation:** reviewer-only endpoint returns event evidence and the available session timeline.
- **Selective containment:** email/purchase submission can be restricted while supplier reads remain possible.
- **Approval binding:** approvals include agent, task, tool, canonical argument hash, target and expiry.
- **Recovery:** recovery records can be inspected, but the full five-step ordered recovery state machine is not production-complete.

## Optional OpenAI integration

Install the optional SDK with `python -m pip install -r optional-requirements.txt`, set `OPENAI_API_KEY`, and restart. The LLM layer is fail-open and can only raise risk from an ALLOW to a HOLD; it cannot lower a deterministic denial. Evidence is redacted before optional summarization. No key or network is required for tests. The simulated ProcurementAgent remains deterministic; a full LLM-driven agent mode is not implemented.

## Frontend development

The React/Vite source is under `frontend/src`. From `frontend/`, run `npm ci && npm run build`, then restart the backend. **Build limitation:** package-registry access timed out in the build environment, and a matching lockfile could not be generated here. The bundled `frontend/dist` remains the prior static dashboard bundle with a reviewer-token prompt patch; it is not verified as a Vite build of the React source. This is a known packaging defect, not a successful React-build claim.

## Evaluation

The Evaluation endpoint computes metrics from stored scenario runs and event latencies. Scenario runs are local simulated workloads only. The UI must display: **“Computed from local scenario runs; no external benchmark results are claimed.”** No external benchmark or production accuracy is claimed. The AgentDojo-style adapter is an extension stub only.

## Known limitations (important)

- The requested normalized tables (`roles`, `agents`, `resources`, `tasks`, `events`, `approvals`, `alerts`, `baselines`, `restrictions`, `taint_markers`, `sessions`, `recovery_steps`, `scenario_runs`) are not implemented as separate SQLAlchemy models; records are stored in one generic table. Database-level append-only guarantees, migrations, row locks and atomic per-agent concurrency guards are not implemented.
- The frontend React source and shipped `dist` are not proven to match; `npm ci && npm run build` could not be completed because npm registry access timed out. The shipped dashboard bundle is static and has fewer features than the requested full admin console.
- Rate limiting, a complete recovery wizard/state machine, human-verified baseline learning from actual observed profiles, fully audited review actions, complete event filtering/pagination, and task lifecycle edge cases remain incomplete.
- Some scenario workflows use real gateway calls and persisted records, but isolation is by unique scenario agent/task/session namespaces rather than a fresh database per scenario. Recovery and role-version scenarios are demonstration-level, not a production incident-response workflow.
- The local demo token is deliberately public and must never be used outside a local isolated demo. The `AGENTWATCH_SECRET` fallback is for development only.
- Docker was unavailable in the build environment, so `docker compose config` and container startup were not validated.
