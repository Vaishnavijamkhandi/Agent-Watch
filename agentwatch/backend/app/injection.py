"""Weighted, explainable indirect-prompt-injection detector and sanitizer."""
from __future__ import annotations
import re
from typing import Any

RULES = [
    ("instruction_override", 4, re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+)?(the\s+)?(previous|prior|above|system|developer)\s+(instructions?|rules?|prompts?)\b", re.I)),
    ("system_prompt_override", 4, re.compile(r"\b(ignore|disregard)\s+(the\s+)?(prior|previous|above)\s+system\s+prompt\b", re.I)),
    ("role_priority_override", 4, re.compile(r"\b(you are now|new (system )?role|highest priority|override (the )?(system|developer)|act as administrator)\b", re.I)),
    ("cross_department_request", 4, re.compile(r"\b(read|access|retrieve|dump|open)\b.{0,90}\b(HR|salary|payroll|personnel|finance|other department)\b", re.I)),
    ("exfiltration_external", 4, re.compile(r"\b(send|email|forward|exfiltrate|upload|transmit)\b.{0,120}(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|https?://|external address|outside the company)", re.I)),
    ("hidden_html_comment", 3, re.compile(r"<!--[\s\S]*?(?:ignore|override|send|read|access|priority|instruction)[\s\S]*?-->", re.I)),
    ("zero_width", 3, re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")),
    ("hidden_style_hint", 3, re.compile(r"(?:color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255\s*,\s*255\s*,\s*255\))|display\s*:\s*none|visibility\s*:\s*hidden).{0,160}(?:instruction|ignore|send|read|override)", re.I)),
    ("directive_to_external", 3, re.compile(r"\b(send|email|forward)\b.{0,100}\b(to|at)\b.{0,50}(?:attacker|external|personal email|gmail\.com|outlook\.com)", re.I)),
]
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

def scan_injection(text: str, threshold: int = 4) -> dict[str, Any]:
    matches=[]
    for name, weight, pattern in RULES:
        for m in pattern.finditer(text):
            matches.append({"rule": name, "weight": weight, "start": m.start(), "end": m.end(), "span": m.group(0)})
    # Deduplicate overlapping matches for scoring but preserve all rule evidence.
    score=sum(x["weight"] for x in matches)
    confidence=min(0.99, 0.25 + 0.12 * score) if matches else 0.05
    return {"tainted": score >= threshold, "score": score, "threshold": threshold,
            "matched_rules": list(dict.fromkeys(x["rule"] for x in matches)),
            "patterns": list(dict.fromkeys(x["rule"] for x in matches)),
            "confidence": round(confidence, 2),
            "spans": [{k:v for k,v in x.items() if k != "span"} for x in matches],
            "_matches": matches}

def sanitize_content(text: str, scan: dict[str, Any] | None = None) -> str:
    scan = scan or scan_injection(text)
    spans=sorted({(x["start"],x["end"]) for x in scan.get("_matches",[])}, reverse=True)
    out=text
    for start,end in spans:
        out=out[:start] + "[SUSPICIOUS DIRECTIVE REMOVED]" + out[end:]
    out=ZERO_WIDTH.sub("", out)
    # Remove any remaining comments, including non-matched comments, so hidden payloads are not rendered.
    out=re.sub(r"<!--[\s\S]*?-->", "[HTML COMMENT REMOVED]", out)
    if scan.get("tainted"):
        return "SECURITY NOTICE: This document contained suspected indirect instructions. Removed content is not executable policy.\n\n" + out
    return out
