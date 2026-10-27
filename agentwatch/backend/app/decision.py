"""Decision vocabulary and deterministic risk scoring helpers."""
from __future__ import annotations
from math import pow
from typing import Iterable

DECISIONS={'ALLOW','DENY','HOLD','QUARANTINE'}

def risk_contribution(decision: str, *, severe: bool=False) -> float:
    """Return event-local risk, never the running cumulative total."""
    if decision=='ALLOW' or decision=='HOLD': return 0.0
    if decision=='QUARANTINE': return 0.0
    if decision=='DENY': return 10.0 if severe else 5.0
    return 0.0

def decayed_risk(events: Iterable[dict], now: float, half_life_hours: float=24.0) -> float:
    half_life=max(1.0,float(half_life_hours))*3600.0
    return sum(float(e.get('drift_score',0))*pow(0.5,max(0.0,now-float(e.get('timestamp',now)))/half_life) for e in events)

def escalation(cumulative: float, hold_threshold: float=12.0, quarantine_threshold: float=20.0) -> str | None:
    if cumulative >= quarantine_threshold: return 'QUARANTINE'
    if cumulative >= hold_threshold: return 'HOLD'
    return None

def never_downgrade(deterministic: str, llm_raise_risk: bool) -> str:
    """LLM advice may only raise ALLOW to HOLD; it never reduces a decision."""
    if deterministic=='ALLOW' and llm_raise_risk: return 'HOLD'
    return deterministic
