import json
import pytest
from contractbridge import engine, repair


def test_freeze_bounded_repair_case(tmp_path):
    contract = {
        'versions': [{'version': 'v1', 'signature': ['/legacy']},
                     {'version': 'v2', 'signature': ['/new']}],
        'required': ['id', 'amount', 'level'],
        'rules': [{'target': 'id', 'source': '/entity_id'},
                  {'target': 'amount', 'source': '/legacy/value', 'op': 'scale', 'factor': 100},
                  {'target': 'level', 'source': '/legacy/tier', 'op': 'enum',
                   'values': {'1': 'low', '2': 'high'}}],
    }
    db = tmp_path / 'ledger.db'
    digest = engine.freeze(db, contract)
    source = tmp_path / 'source.jsonl'
    source.write_text(json.dumps({'version': 'v1', 'entity_id': 'A', 'subject': 'S',
                                  'legacy': {}, 'status': 'ok'}))
    engine.ingest(db, source, contract)
    engine.translate(db, digest)
    assert engine.verify(db, digest)[0]['issues'] == ['required_missing']
    case = {'id': 'case-A', 'contract_hash': digest, 'envelope_ids': [1],
            'proposals': [{'envelope_id': 1, 'path': '/legacy',
                           'value': {'value': 2, 'tier': 1}, 'cost': 5},
                          {'envelope_id': 1, 'path': '/legacy/value', 'value': 2, 'cost': 2},
                          {'envelope_id': 1, 'path': '/legacy/tier', 'value': 1, 'cost': 2}]}
    first = repair.open_case(db, case)
    assert repair.open_case(db, case) == first
    assert repair.describe(db, 'case-A')['case'] == case
    changed = dict(case, proposals=[dict(case['proposals'][0], value=3)])
    with pytest.raises(ValueError, match='repair_case_conflict'):
        repair.open_case(db, changed)
