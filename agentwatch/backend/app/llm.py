"""Optional LLM second opinion. Deterministic policy remains authoritative; LLM may only raise risk."""
import os, re, json

def redact_secrets(text: str) -> str:
    text=re.sub(r'(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+',r'\1=[REDACTED]',text)
    text=re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b','[EMAIL_REDACTED]',text)
    return text

def llm_active() -> bool:
    return bool(os.getenv('OPENAI_API_KEY'))

def task_alignment_second_opinion(task: str, action: str, *, client=None, timeout: float=2.0) -> dict:
    if not llm_active(): return {'active':False,'risk_raise':False,'reason':'LLM disabled; deterministic checks only'}
    try:
        if client is None:
            from openai import OpenAI
            client=OpenAI(timeout=timeout,max_retries=0)
        response=client.chat.completions.create(model=os.getenv('AGENTWATCH_LLM_MODEL','gpt-4o-mini'),temperature=0,
          messages=[{'role':'system','content':'Assess task alignment. Return JSON {"out_of_scope": boolean, "reason": string}. Never authorize an action.'},
                    {'role':'user','content':json.dumps({'task':redact_secrets(task),'proposed_action':redact_secrets(action)})}],timeout=timeout)
        content=response.choices[0].message.content or '{}'; data=json.loads(content)
        return {'active':True,'risk_raise':bool(data.get('out_of_scope')),'reason':str(data.get('reason','LLM assessment'))[:500]}
    except Exception as exc:
        return {'active':True,'risk_raise':False,'reason':'LLM unavailable; deterministic path retained ('+type(exc).__name__+')'}

def summarize_evidence(evidence: dict, *, client=None, timeout: float=2.0) -> str:
    if not llm_active(): return 'Deterministic evidence summary: '+redact_secrets(json.dumps(evidence,default=str))[:800]
    try:
        if client is None:
            from openai import OpenAI
            client=OpenAI(timeout=timeout,max_retries=0)
        response=client.chat.completions.create(model=os.getenv('AGENTWATCH_LLM_MODEL','gpt-4o-mini'),temperature=0,
          messages=[{'role':'system','content':'Summarize security evidence without attributing a proven attacker or revealing secrets.'},{'role':'user','content':redact_secrets(json.dumps(evidence,default=str))[:4000]}],timeout=timeout)
        return redact_secrets(response.choices[0].message.content or 'Evidence summary unavailable.')[:1000]
    except Exception:
        return 'Deterministic evidence summary: '+redact_secrets(json.dumps(evidence,default=str))[:800]
