"""Trusted deterministic mock protected-tool executors; agent-supplied credentials are not used."""
from __future__ import annotations
import uuid
from fastapi import HTTPException
from .injection import scan_injection, sanitize_content

def execute_tool(db, call):
    # Import persistence helpers lazily to avoid a module import cycle with the API.
    from .main import get, all_rows, add, now, digest
    params=call.params; tool=call.tool
    target=str(params.get('resource_id') or params.get('target') or params.get('vendor_id') or '')
    if tool=='document.read':
        resource=get(db,'resources',target)
        if not resource: raise HTTPException(404,'Resource not found')
        scan=scan_injection(resource['content']); content_hash=digest(resource['content']); sanitized=sanitize_content(resource['content'],scan)
        output={'resource_id':target,'sanitized_content':sanitized,'content_flags':{k:v for k,v in scan.items() if not k.startswith('_')},'content':sanitized}
        if scan['tainted']:
            existing=[m for m in all_rows(db,'taint_markers') if m.get('session_id')==call.session_id and m.get('resource_id')==target and m.get('content_hash')==content_hash]
            if not existing:
                task=get(db,'tasks',call.task_id)
                marker={'id':str(uuid.uuid4()),'resource_id':target,'patterns':scan['matched_rules'],'score':scan['score'],'confidence':scan['confidence'],'content_hash':content_hash,'agent_id':task.get('agent_id') if task else None,'created_at':now(),'session_id':call.session_id}
                add(db,'taint_markers',marker,marker['id'])
            output['security_warning']='Suspected indirect prompt injection detected; matched spans were removed and content is flagged.'
        return output, bool(scan['tainted'])
    if tool=='supplier.search': return {'suppliers':['Supplier A','Supplier B'],'resources':['Quote-A','Quote-B','Quote-C','Quote-D','Quote-E']},False
    if tool=='purchase.prepare': return {'purchase_request_id':'PR-'+uuid.uuid4().hex[:8].upper(),'status':'draft','submitted':False,'details':params},False
    if tool=='email.send': return {'message_id':'MAIL-'+uuid.uuid4().hex[:8].upper(),'status':'sent','to':params.get('to')},False
    if tool=='purchase.submit': return {'status':'submitted'},False
    raise HTTPException(400,'Unknown tool')
