import json
from pathlib import Path

import pytest

from contractbridge import canary, engine, migration

FIXTURE=Path(__file__).resolve().parents[1]/'fixtures'/'migration-canary.json'


def prepared(tmp_path):
    db=tmp_path/'ledger.db'
    base={'versions':[{'version':'v1','signature':['/legacy']},
                      {'version':'v2','signature':['/new']}],
          'required':['id','amount'],
          'rules':[{'target':'id','source':'/entity_id'},
                   {'target':'amount','source':'/legacy/value','op':'scale','factor':100}],
          'errors':{}}
    baseline=engine.freeze(db,base)
    source=tmp_path/'source.jsonl'
    source.write_text('\n'.join(json.dumps({'version':'v1','entity_id':f'E-{i}',
                         'subject':f'S-{i}','legacy':{'value':i+1}}) for i in range(4)),encoding='utf-8')
    engine.ingest(db,source,base)
    engine.translate(db,baseline)
    target=json.loads(json.dumps(base))
    target['versions'][1]['version']='v3'
    target['rules'][1]['factor']=101
    target_hash=engine.freeze(db,target)
    engine.translate(db,target_hash)
    migration.plan(db,'cutover',baseline,target_hash,10)
    return db


def test_canary_fixture_freezes_strata_and_selection(tmp_path):
    db=prepared(tmp_path)
    first=canary.load_fixture(db,FIXTURE)
    second=canary.load_fixture(db,FIXTURE)
    assert first==second
    assert first['design']['strata'][0]['selected_ids']==[1]
    assert first['design']['strata'][1]['selected_ids']==[3]
    assert canary.inspect(db,'migration-canary-demo')['frame_hash']==first['frame_hash']


def test_canary_rejects_duplicate_or_unknown_frame(tmp_path):
    db=prepared(tmp_path)
    design=json.loads(FIXTURE.read_text(encoding='utf-8'))['design']
    design['strata'][1]['frame_ids']=[2,4]
    with pytest.raises(ValueError,match='invalid_canary_selection'):
        canary.register(db,'bad','cutover',design)
    design['strata'][1]['frame_ids']=[3,99]
    with pytest.raises(ValueError,match='unknown_canary_envelope'):
        canary.register(db,'bad','cutover',design)
