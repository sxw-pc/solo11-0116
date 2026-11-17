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
    from . import transactions
    transactions.validate_transaction_contract(contract)
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
        if old:
            # The bytes are already frozen, but another contract may recognize
            # the same envelope rows through its own signatures. Recognition is
            # recorded per (envelope, contract); the envelope's primary version
            # column is never rewritten.
            sid=old['id'];contract_row=db.execute('SELECT id FROM contract WHERE hash=?',(sha(canonical(contract).encode()),)).fetchone()
            contract_pk=contract_row['id'] if contract_row else None
            for e in db.execute('SELECT * FROM envelope WHERE source_id=? ORDER BY line_no',(sid,)):
                obj=json.loads(e['raw']);version=identify(obj,contract)
                if version and contract_pk:
                    db.execute('INSERT OR IGNORE INTO envelope_version(envelope_id,contract_id,version) VALUES (?,?,?)',(e['id'],contract_pk,version))
                    if not e['version']:
                        db.execute('UPDATE envelope SET version=?,status=? WHERE id=?',(version,'已识别版本',e['id']))
                        db.execute("DELETE FROM issue WHERE envelope_id=? AND code='version_ambiguous'",(e['id'],))
            return 0
        sid=db.execute('INSERT INTO source(hash,body) VALUES (?,?)',(sha(raw),raw)).lastrowid
        contract_row=db.execute('SELECT id FROM contract WHERE hash=?',(sha(canonical(contract).encode()),)).fetchone()
        contract_pk=contract_row['id'] if contract_row else None
        for line_no,line in enumerate(raw.decode().splitlines(),1):
            try:
                obj=json.loads(line);version=identify(obj,contract)
                status='已识别版本' if version else '待核'
                eid=db.execute('INSERT INTO envelope(source_id,line_no,version,status,raw,entity_id) VALUES (?,?,?,?,?,?)',(sid,line_no,version,status,line,normalize_identity(obj,contract))).lastrowid
                if version and contract_pk:
                    db.execute('INSERT OR IGNORE INTO envelope_version(envelope_id,contract_id,version) VALUES (?,?,?)',(eid,contract_pk,version))
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
        contract_versions={x['version'] for x in contract['versions']}
        recognized={r['envelope_id']:r['version'] for r in db.execute(
            'SELECT envelope_id,version FROM envelope_version WHERE contract_id=?',(row['id'],))}
        for src in db.execute('SELECT * FROM source'):
            existing=db.execute('SELECT id FROM run WHERE source_id=? AND contract_id=?',(src['id'],row['id'])).fetchone()
            if existing:
                rid=existing['id']
                done={r['envelope_id'] for r in db.execute('SELECT envelope_id FROM output WHERE run_id=?',(rid,))}
                # Envelopes that failed translation produced issues instead of
                # outputs; they were processed too and must not be replayed.
                done |= {r['envelope_id'] for r in db.execute(
                    'SELECT DISTINCT envelope_id FROM issue WHERE run_id=? AND envelope_id IS NOT NULL',(rid,))}
                pending=[e for e in db.execute('SELECT * FROM envelope WHERE source_id=? ORDER BY line_no',(src['id'],))
                         if e['id'] not in done and e['id'] in recognized]
                if not pending:
                    outputs.extend(x['id'] for x in db.execute('SELECT id FROM output WHERE run_id=?',(rid,)))
                    continue
            else:
                rid=db.execute("INSERT INTO run(source_id,contract_id,status) VALUES (?,?,'待解析')",(src['id'],row['id'])).lastrowid
                pending=[dict(x) for x in db.execute('SELECT * FROM envelope WHERE source_id=? ORDER BY line_no',(src['id'],))]
            # Recognition is per (envelope, contract): the same raw envelope can
            # belong to two frozen contracts via their distinct signatures.
            envelopes=pending
            seen={};states={};bad=False
            for e in envelopes:
                scoped_version=recognized.get(e['id'], e['version'] if e['version'] in contract_versions else None)
                if not scoped_version:
                    if not e['version']:bad=True
                    continue
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
                bad |= bool(issues)
            run_bad=bad or bool(db.execute(
                "SELECT 1 FROM output WHERE run_id=? AND status='待核' LIMIT 1",(rid,)).fetchone())
            db.execute('UPDATE run SET status=? WHERE id=?',('待核' if run_bad else '已核验',rid))
            outputs.extend(x['id'] for x in db.execute('SELECT id FROM output WHERE run_id=?',(rid,)))
    db.close();reconcile(db_path)
    if contract.get('transaction'):
        from . import transactions
        transactions.reconcile_transactions(db_path,contract_hash)
    return outputs
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
    for row in db.execute('''SELECT o.* FROM output o JOIN run r ON r.id=o.run_id
        JOIN contract c ON c.id=r.contract_id WHERE c.hash=?''',(contract_hash,)):
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
    contract_row=db.execute('SELECT id,body FROM contract WHERE hash=?',(contract_hash,)).fetchone()
    if contract_row and json.loads(contract_row['body']).get('transaction'):
        obj['transactions']=[]
        for tr in db.execute('SELECT * FROM transaction_record WHERE contract_id=? ORDER BY transaction_id',(contract_row['id'],)):
            item=dict(tr);item['events']=[dict(e) for e in db.execute('''SELECT te.*,s.hash AS source_hash
                FROM transaction_event te JOIN envelope en ON en.id=te.envelope_id
                JOIN source s ON s.id=en.source_id WHERE te.transaction_pk=? ORDER BY te.ordinal''',(tr['id'],))]
            item['gaps']=[dict(g) for g in db.execute('SELECT output_id,code,detail FROM transaction_gap WHERE transaction_pk=? ORDER BY id',(tr['id'],))]
            obj['transactions'].append(item)
        obj['unattached_gaps']=[dict(g) for g in db.execute(
            'SELECT output_id,code,detail FROM transaction_gap WHERE transaction_pk IS NULL ORDER BY id')]
    path=Path(path);path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
    md='# 契约转译报告\n\n'+f"输出 {len(obj['outputs'])} 条，问题 {len(obj['issues'])} 条。\n"
    if 'transactions' in obj:
        md+=f"\n## 跨接口交易核对\n\n交易 {len(obj['transactions'])} 笔，游离证据 {len(obj['unattached_gaps'])} 条。\n"
        for tr in obj['transactions']:
            md+=(f"\n### 交易 {tr['transaction_id']}（{tr['protocol']} → {tr['status']}）\n\n"
                 f"授权 {tr['authorized']} / 扣款 {tr['captured']} / 退款 {tr['refunded']} / "
                 f"撤销 {tr['voided']} / 可退余额 {tr['refundable']}\n\n事件链：\n\n")
            for e in tr['events']:
                md+=(f"{e['ordinal']}. {e['event_time']} {e['event']} {e['amount']} "
                     f"(output {e['output_id']}, envelope {e['envelope_id']}, source {e['source_hash'][:12]}, "
                     f"key {e['event_key']}, replay×{e['replay_count']})\n")
            if tr['gaps']:
                md+='\n缺口：\n\n'+'\n'.join(f"- {g['code']}: {g['detail']}" for g in tr['gaps'])+'\n'
        if obj['unattached_gaps']:
            md+='\n游离缺口：\n\n'+'\n'.join(f"- {g['code']}: {g['detail']}" for g in obj['unattached_gaps'])+'\n'
    path.with_suffix('.md').write_text(md,encoding='utf-8');db.close();return path
