"""Individually testable, typed pipeline check results."""
from dataclasses import dataclass
from typing import Any
@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str
    risk: float = 0.0
    evidence: dict[str, Any] | None = None

def identity_check(agent: dict | None) -> CheckResult:
    return CheckResult('Identity', bool(agent), 'Authenticated identity' if agent else 'Invalid agent identity', 100 if not agent else 0)
def state_check(agent: dict, restrictions: list[dict], tool: str) -> CheckResult:
    ok=agent.get('state')!='quarantined' and not any(r.get('active') and r.get('tool')==tool for r in restrictions)
    return CheckResult('Agent state',ok,'Agent active and tool unrestricted' if ok else 'Quarantined or matching tool restriction',80 if not ok else 0)
def role_check(role: dict | None, version: int, tool: str) -> CheckResult:
    ok=bool(role and role.get('status')=='approved' and role.get('version')==version and tool in role.get('allowed_tools',[]))
    return CheckResult('Approved role',ok,'Tool allowed by current approved role' if ok else 'Role version unapproved or tool not permitted',60 if not ok else 0)
def classification_check(resource: dict | None, role: dict) -> CheckResult:
    category=(resource or {}).get('classification','unknown')
    ok=bool(resource and category in role.get('allowed_data_categories',[]))
    return CheckResult('Trusted classification',ok,f'Trusted registry classification: {category}',70 if not ok else 0,{'classification':category})
def task_scope_check(target: str, task: dict, tool: str) -> CheckResult:
    scoped=target in task.get('approved_resources',[]) if target else tool in ('supplier.search','purchase.prepare','email.send')
    return CheckResult('Task relevance',scoped,f'Target in task scope={scoped}',50 if not scoped else 0)
def behavior_context_check(tainted: bool, sensitive: bool) -> CheckResult:
    ok=not (tainted and sensitive)
    return CheckResult('Behavior context',ok,'No recent taint affecting this action' if ok else 'Recent tainted output affects this sensitive/out-of-task action',80 if not ok else 0)
def approval_check(required: bool, matched: bool) -> CheckResult:
    ok=not required or matched
    return CheckResult('Approval binding',ok,'Exact unexpired approval present' if ok else 'Exact unexpired approval required',0 if ok else 2)
def cold_start_check(has_baseline: bool, trivial: bool, exact_approval: bool=False) -> CheckResult:
    ok=has_baseline or trivial or exact_approval
    return CheckResult('Cold-start baseline',ok,'Baseline, in-scope trivial action, or exact approval present' if ok else 'No baseline; non-trivial action held conservatively',0 if ok else 5)
def delegation_check(tool: str, target: str, scope: dict | None, parent_resources: list[str] | None=None) -> CheckResult:
    if scope is None: return CheckResult('Delegation',True,'No parent delegation applies')
    ok=tool in scope.get('allowed_tools',[]) and (not target or target in scope.get('approved_resources',[])) and (parent_resources is None or not target or target in parent_resources)
    return CheckResult('Delegation',ok,'Within delegated scope' if ok else 'Child exceeded delegated scope',70 if not ok else 0)
