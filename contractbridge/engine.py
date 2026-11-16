import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from .store import connect
def sha(x):return hashlib.sha256(x).hexdigest()
def event_instant(value):
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def ordered_rules(contract):
    by_target={rule['target']:rule for rule in contract['rules']}
    if len(by_target)!=len(contract['rules']):raise ValueError('target_conflict')
    ordered=[];active=set();done=set()
    def visit(target):
        if target in active:raise ValueError('mapping_cycle')
        if target in done:return
        active.add(target);rule=by_target[target]
        if rule.get('op')=='chain':
            source=rule.get('source','')
            if not source.startswith('$') or source[1:] not in by_target:raise ValueError('unknown_chain_source')
            visit(source[1:])
        active.remove(target);done.add(target);ordered.append(rule)
    for target in by_target:visit(target)
    return ordered

def pointer(obj,path):
    cur=obj
    for part in path.strip('/').split('/'):
        if not isinstance(cur,dict) or part not in cur:return False,None
        cur=cur[part]
    return True,cur
def freeze(db_path,contract):
    versions={x['version'] for x in contract['versions']}
    if len(versions)!=2 or len(contract['versions'])!=2:raise ValueError('two_versions_required')
    ordered_rules(contract)
    targets={rule['target'] for rule in contract['rules']}
    required=set(contract['required'])
    if not required.issubset(targets):raise ValueError('required_unmapped')
    body=canonical(contract);h=sha(body.encode());db=connect(db_path)
    target_version=contract['versions'][-1]['version']
    with db:
        existing=db.execute('SELECT hash FROM contract WHERE version=?',(target_version,)).fetchone()
        if existing and existing['hash']!=h:raise ValueError('contract_version_conflict')
        db.execute('INSERT OR IGNORE INTO contract(version,hash,body) VALUES (?,?,?)',(target_version,h,body))
    db.close();return h
def identify(obj,contract):
    version=obj.get('version')
    options={x['version'] for x in contract['versions']}
    signatures=[x['version'] for x in contract['versions'] if all(pointer(obj,p)[0] for p in x.get('signature',[]))]
    if version in options:
        return version if not signatures or signatures==[version] else None
    return signatures[0] if len(signatures)==1 else None
def normalize_identity(obj,contract):
    explicit=obj.get('entity_id')
    if explicit:return str(explicit)
    paths=contract.get('identity_parts',[])
    if not paths:return ''
    values=[]
    for path in paths:
        exists,value=pointer(obj,path)
        if not exists or value in (None,''):return ''
        values.append(str(value).replace('|','||'))
    return '|'.join(values)
def ingest(db_path,path,contract):
    raw=Path(path).read_bytes();db=connect(db_path);count=0
    with db:
        old=db.execute('SELECT id FROM source WHERE hash=?',(sha(raw),)).fetchone()
        if old:return 0
        sid=db.execute('INSERT INTO source(hash,body) VALUES (?,?)',(sha(raw),raw)).lastrowid
        for line_no,line in enumerate(raw.decode().splitlines(),1):
            try:
                obj=json.loads(line);version=identify(obj,contract)
                status='已识别版本' if version else '待核'
                eid=db.execute('INSERT INTO envelope(source_id,line_no,version,status,raw,entity_id) VALUES (?,?,?,?,?,?)',(sid,line_no,version,status,line,normalize_identity(obj,contract))).lastrowid
                if not version:db.execute('INSERT INTO issue(envelope_id,code,detail) VALUES (?,?,?)',(eid,'version_ambiguous',line))
                count+=1
            except (ValueError,json.JSONDecodeError) as exc:
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('parse_error',f'{line_no}:{exc}'))
    db.close();return count
def transform(obj,contract):
    out={};evidence=[];issues=[]
    for rule in ordered_rules(contract):
        target=rule['target'];op=rule.get('op','copy')
        if op=='chain':
            source_target=rule['source'][1:]
            exists=source_target in out;value=out.get(source_target)
        else:exists,value=pointer(obj,rule['source'])
        if not exists:
            if 'default' in rule:
                value=rule['default'];exists=True;evidence.append((target,None,'default'))
            elif target in contract['required']:issues.append(('required_missing',target));continue
            else:continue
        if value is None and not rule.get('nullable',False):issues.append(('null_forbidden',target));continue
        if op=='enum' and value is not None:
            mapping=rule['values']
            if str(value) not in mapping:issues.append(('enum_unknown',target));continue
            value=mapping[str(value)]
        if op=='scale' and value is not None:
            try:value=float(value)*float(rule['factor'])
            except (ValueError,TypeError):issues.append(('scale_invalid',target));continue
        out[target]=value
        if not any(x[0]==target for x in evidence):evidence.append((target,rule['source'],op))
    status=obj.get('status','ok')
    if status in contract.get('errors',{}):out['status']=contract['errors'][status]
    elif status!='ok':issues.append(('error_unknown',str(status)))
    else:out['status']='ok'
    evidence.append(('status','/status','error_map'))
    return out,evidence,issues
def translate(db_path,contract_hash):
    db=connect(db_path);row=db.execute('SELECT * FROM contract WHERE hash=?',(contract_hash,)).fetchone()
    if not row:raise ValueError('unknown_contract')
    contract=json.loads(row['body']);outputs=[]
    with db:
        for src in db.execute('SELECT * FROM source'):
            existing=db.execute('SELECT id FROM run WHERE source_id=? AND contract_id=?',(src['id'],row['id'])).fetchone()
            if existing:
                outputs.extend(x['id'] for x in db.execute('SELECT id FROM output WHERE run_id=?',(existing['id'],)))
                continue
            rid=db.execute("INSERT INTO run(source_id,contract_id,status) VALUES (?,?,'待解析')",(src['id'],row['id'])).lastrowid
            envelopes=[dict(x) for x in db.execute('SELECT * FROM envelope WHERE source_id=? ORDER BY line_no',(src['id'],))]
            seen={};states={};bad=False
            for e in envelopes:
                if not e['version']:bad=True;continue
                obj=json.loads(e['raw']);obj['entity_id']=e['entity_id'];subject=str(obj.get('subject',''));identity=e['entity_id']
                if not identity or not subject:db.execute('INSERT INTO issue(envelope_id,run_id,code,detail) VALUES (?,?,?,?)',(e['id'],rid,'identity_missing',identity));bad=True;continue
                if identity in seen and seen[identity]!=subject:
                    db.execute('INSERT INTO issue(envelope_id,run_id,code,detail) VALUES (?,?,?,?)',(e['id'],rid,'identity_conflict',identity));bad=True;continue
                seen[identity]=subject
                state=obj.get('state')
                event_time=obj.get('event_time')
                if state is not None and event_time is not None:
                    previous=states.get(identity)
                    if previous and event_instant(event_time)<previous[0]:
                        db.execute('INSERT INTO issue(envelope_id,run_id,code,detail) VALUES (?,?,?,?)',(e['id'],rid,'state_regression',identity));bad=True
                    states[identity]=(event_instant(event_time),state)
                old=db.execute('SELECT subject FROM entity WHERE id=?',(identity,)).fetchone()
                if old and old['subject']!=subject:
                    db.execute('INSERT INTO issue(envelope_id,run_id,code,detail) VALUES (?,?,?,?)',(e['id'],rid,'identity_conflict',identity));bad=True;continue
                db.execute('INSERT OR IGNORE INTO entity VALUES (?,?)',(identity,subject))
                output,evidence,issues=transform(obj,contract)
                for code,detail in issues:db.execute('INSERT INTO issue(envelope_id,run_id,code,detail) VALUES (?,?,?,?)',(e['id'],rid,code,detail))
                state='待核' if issues else '已核验';body=canonical(output)
                oid=db.execute('INSERT INTO output(run_id,envelope_id,body,hash,status) VALUES (?,?,?,?,?)',(rid,e['id'],body,sha(body.encode()),state)).lastrowid
                for field,pointer_path,rule in evidence:db.execute('INSERT INTO evidence VALUES (?,?,?,?)',(oid,field,pointer_path,rule))
                bad |= bool(issues);outputs.append(oid)
            db.execute('UPDATE run SET status=? WHERE id=?',('待核' if bad else '已核验',rid))
    db.close();reconcile(db_path);return outputs
def reconcile(db_path):
    db=connect(db_path);groups={};issues=[]
    with db:
        db.execute("DELETE FROM issue WHERE code IN ('cross_package_identity','cross_package_state','state_transition')")
        envelopes=[dict(x) for x in db.execute('SELECT * FROM envelope WHERE version IS NOT NULL ORDER BY id')]
        for e in envelopes:
            obj=json.loads(e['raw']);identity=e['entity_id']
            if identity:groups.setdefault(identity,[]).append((e,obj))
        for identity,items in groups.items():
            subjects={str(obj.get('subject','')) for _,obj in items}
            if len(subjects)>1:
                for e,_ in items:issues.append((e['id'],'cross_package_identity',identity))
            dated=sorted([(event_instant(obj['event_time']),obj['state'],e['id']) for e,obj in items if obj.get('event_time') and obj.get('state')])
            previous=None
            allowed={'new':{'new','active','closed'},'active':{'active','closed'},'closed':{'closed','reopened'},'reopened':{'reopened','active','closed'}}
            for time,state,eid in dated:
                if previous and time==previous[0] and state!=previous[1]:issues.append((eid,'cross_package_state',identity))
                if previous and state not in allowed.get(previous[1],{state}):issues.append((eid,'state_transition',identity))
                previous=(time,state)
        for eid,code,detail in issues:
            db.execute('INSERT INTO issue(envelope_id,code,detail) VALUES (?,?,?)',(eid,code,detail))
            db.execute("UPDATE output SET status='待核' WHERE envelope_id=?",(eid,))
            db.execute("UPDATE run SET status='待核' WHERE id IN (SELECT run_id FROM output WHERE envelope_id=?)",(eid,))
    db.close();return issues
def verify(db_path,contract_hash):
    db=connect(db_path);contract=json.loads(db.execute('SELECT body FROM contract WHERE hash=?',(contract_hash,)).fetchone()['body']);results=[]
    for row in db.execute('SELECT * FROM output'):
        obj=json.loads(row['body']);codes=[]
        if sha(row['body'].encode())!=row['hash']:codes.append('output_hash')
        if any(x not in obj for x in contract['required']):codes.append('required_missing')
        if obj.get('status') not in set(contract.get('errors',{}).values())|{'ok'}:codes.append('status_invalid')
        envelope=db.execute('SELECT raw,entity_id FROM envelope WHERE id=?',(row['envelope_id'],)).fetchone()
        if envelope is None:codes.append('source_missing')
        else:
            source=json.loads(envelope['raw']);source['entity_id']=envelope['entity_id']
            expected,expected_evidence,_=transform(source,contract)
            if canonical(expected)!=row['body']:codes.append('business_mismatch')
            actual_evidence={(x['field'],x['pointer'],x['rule']) for x in db.execute(
                'SELECT field,pointer,rule FROM evidence WHERE output_id=?',(row['id'],))}
            if actual_evidence!=set(expected_evidence):codes.append('evidence_mismatch')
        results.append({'id':row['id'],'status':'拒绝' if codes else row['status'],'issues':codes})
    db.close();return results
def report(db_path,contract_hash,path):
    db=connect(db_path);obj={'verify':verify(db_path,contract_hash),'outputs':[],'issues':[dict(x) for x in db.execute('SELECT code,detail,envelope_id,run_id FROM issue')]}
    for o in db.execute('SELECT o.*,s.hash AS source_hash,e.line_no FROM output o JOIN envelope e ON e.id=o.envelope_id JOIN source s ON s.id=e.source_id'):
        x=dict(o);x['evidence']=[dict(e) for e in db.execute('SELECT field,pointer,rule FROM evidence WHERE output_id=?',(o['id'],))];obj['outputs'].append(x)
    path=Path(path);path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8');path.with_suffix('.md').write_text('# 契约转译报告\n\n'+f"输出 {len(obj['outputs'])} 条，问题 {len(obj['issues'])} 条。\n",encoding='utf-8');db.close();return path
