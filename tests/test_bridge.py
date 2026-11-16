import json
import pytest
from contractbridge import engine
def cfg():return {'versions':[{'version':'v1','signature':['/legacy']},{'version':'v2','signature':['/new']}],'required':['id','amount'],'rules':[{'target':'id','source':'/entity_id'},{'target':'amount','source':'/legacy/value','op':'scale','factor':100}],'errors':{'TEMP':'retry','FATAL':'failed'}}
def test_contract_validation(tmp_path):
    c=cfg();assert engine.freeze(tmp_path/'db',c)
    c['required'].append('missing')
    with pytest.raises(ValueError):engine.freeze(tmp_path/'db',c)
def test_identify():
    assert engine.identify({'version':'v1'},cfg())=='v1'
    assert engine.identify({'unknown':1},cfg()) is None
def test_transform_null_missing():
    obj={'entity_id':'A','legacy':{'value':2}};out,ev,issues=engine.transform(obj,cfg());assert out['amount']==200 and not issues
    out,ev,issues=engine.transform({'entity_id':'A'},cfg());assert ('required_missing','amount') in issues
def test_ingest_translate_verify(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c);p=tmp_path/'x.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A','subject':'Test','legacy':{'value':2}}));assert engine.ingest(db,p,c)==1
    assert engine.ingest(db,p,c)==0;assert engine.translate(db,h);assert engine.verify(db,h)[0]['status']=='已核验'
    report=json.loads(engine.report(db,h,tmp_path/'r.json').read_text(encoding='utf-8'));assert report['outputs'][0]['evidence']

def test_explicit_version_signature_conflict():
    assert engine.identify({'version':'v1','new':{}},cfg()) is None

def test_enum_and_default_evidence():
    c=cfg();c['rules'].append({'target':'label','source':'/legacy/missing','default':'unknown'})
    c['rules'].append({'target':'level','source':'/legacy/level','op':'enum','values':{'1':'low','2':'high'}})
    out,ev,issues=engine.transform({'entity_id':'A','legacy':{'value':1,'level':2}},c)
    assert out['label']=='unknown' and out['level']=='high'
    assert ('label',None,'default') in ev

def test_unknown_error_never_success():
    out,ev,issues=engine.transform({'entity_id':'A','legacy':{'value':1},'status':'WHAT'},cfg())
    assert ('error_unknown','WHAT') in issues
    assert out.get('status')!='ok'

def test_identity_conflict_and_replay(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c)
    rows=[{'version':'v1','entity_id':'A','subject':'First','legacy':{'value':1}}, {'version':'v1','entity_id':'A','subject':'Second','legacy':{'value':2}}]
    p=tmp_path/'x.jsonl';p.write_text('\n'.join(json.dumps(x) for x in rows))
    engine.ingest(db,p,c);first=engine.translate(db,h);second=engine.translate(db,h)
    assert first==second
    from contractbridge.store import connect
    dbh=connect(db);assert dbh.execute("SELECT count(*) FROM issue WHERE code='identity_conflict'").fetchone()[0]==1

def test_status_regression_flags_run(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c)
    rows=[{'version':'v1','entity_id':'A','subject':'First','legacy':{'value':1},'state':'active','event_time':'2026-01-02'}, {'version':'v1','entity_id':'A','subject':'First','legacy':{'value':2},'state':'new','event_time':'2026-01-01'}]
    p=tmp_path/'x.jsonl';p.write_text('\n'.join(json.dumps(x) for x in rows));engine.ingest(db,p,c);engine.translate(db,h)
    from contractbridge.store import connect
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='state_regression'").fetchone()[0]==1

def test_bad_json_isolated(tmp_path):
    c=cfg();db=tmp_path/'db';engine.freeze(db,c)
    p=tmp_path/'x.jsonl';p.write_text('{bad}\n'+json.dumps({'version':'v1','entity_id':'A','subject':'Test','legacy':{'value':1}}))
    assert engine.ingest(db,p,c)==1
    from contractbridge.store import connect
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='parse_error'").fetchone()[0]==1

def test_cross_package_subject_conflict(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c)
    for name,subject in [('a','First'),('b','Other')]:
        p=tmp_path/f'{name}.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A','subject':subject,'legacy':{'value':1}}));engine.ingest(db,p,c)
    engine.translate(db,h)
    from contractbridge.store import connect
    conn=connect(db)
    assert conn.execute("SELECT count(*) FROM issue WHERE code='cross_package_identity'").fetchone()[0]>=1
    assert conn.execute("SELECT count(*) FROM output WHERE status='待核'").fetchone()[0]>=1

def test_cross_package_state_transition(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c)
    for name,state,time in [('a','closed','2026-01-01T00:00:00Z'),('b','active','2026-01-02T00:00:00Z')]:
        p=tmp_path/f'{name}.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A','subject':'Same','legacy':{'value':1},'state':state,'event_time':time}));engine.ingest(db,p,c)
    engine.translate(db,h)
    from contractbridge.store import connect
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='state_transition'").fetchone()[0]==1

def test_composite_legacy_identity(tmp_path):
    c=cfg();c['identity_parts']=['/legacy/site','/legacy/local_id'];db=tmp_path/'db';h=engine.freeze(db,c)
    p=tmp_path/'x.jsonl';p.write_text(json.dumps({'version':'v1','subject':'Sample','legacy':{'site':'S','local_id':'7','value':2}}))
    engine.ingest(db,p,c);engine.translate(db,h)
    from contractbridge.store import connect
    conn=connect(db)
    assert conn.execute('SELECT entity_id FROM envelope').fetchone()[0]=='S|7'
    assert json.loads(conn.execute('SELECT body FROM output').fetchone()[0])['id']=='S|7'

def test_null_is_distinct_from_missing_default():
    c=cfg();c['rules'].append({'target':'note','source':'/legacy/note','default':'N/A'})
    out,_,issues=engine.transform({'entity_id':'A','legacy':{'value':1}},c)
    assert out['note']=='N/A' and not issues
    out,_,issues=engine.transform({'entity_id':'A','legacy':{'value':1,'note':None}},c)
    assert ('null_forbidden','note') in issues

def test_unknown_enum_stays_unresolved():
    c=cfg();c['rules'].append({'target':'level','source':'/legacy/level','op':'enum','values':{'1':'low'}})
    out,_,issues=engine.transform({'entity_id':'A','legacy':{'value':1,'level':99}},c)
    assert 'level' not in out and ('enum_unknown','level') in issues

def test_known_error_maps_without_success():
    out,_,issues=engine.transform({'entity_id':'A','legacy':{'value':1},'status':'TEMP'},cfg())
    assert out['status']=='retry' and not issues

def test_verify_detects_output_tamper(tmp_path):
    c=cfg();db=tmp_path/'db';h=engine.freeze(db,c)
    p=tmp_path/'x.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A','subject':'Test','legacy':{'value':2}}))
    engine.ingest(db,p,c);engine.translate(db,h)
    from contractbridge.store import connect
    conn=connect(db)
    with conn:conn.execute("UPDATE output SET body='{}'")
    assert engine.verify(db,h)[0]['status']=='拒绝'
