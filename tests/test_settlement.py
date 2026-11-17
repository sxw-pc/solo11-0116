import json
import pytest
from contractbridge import engine, operations, settlement


def test_statement_first_pass_match(tmp_path):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id', 'amount'],
                'rules': [{'target': 'id', 'source': '/entity_id'},
                          {'target': 'amount', 'source': '/legacy/value', 'op': 'scale', 'factor': 100}]}
    db = tmp_path / 'ledger.db'
    digest = engine.freeze(db, contract)
    source = tmp_path / 'source.jsonl'
    source.write_text(json.dumps({'version': 'v1', 'entity_id': 'A', 'subject': 'S',
                                  'legacy': {'value': 1}}))
    engine.ingest(db, source, contract)
    engine.translate(db, digest)
    operations.policy(db, 'consumer', digest, 100)
    delivery = operations.dispatch(db, 'consumer')
    line = {'line_id': 'r1', 'hash_prefix': delivery['items'][0]['hash'], 'amount': 100,
            'result': '接收'}
    statement = tmp_path / 'statement.json'
    statement.write_text(json.dumps({'id': 's1', 'delivery_id': delivery['id'], 'lines': [line]},
                                    ensure_ascii=False), encoding='utf-8')
    first = settlement.import_statement(db, statement)
    assert settlement.import_statement(db, statement) == first
    assert settlement.reconcile(db, 's1')['status'] == '已匹配'
    statement.write_text(statement.read_text(encoding='utf-8').replace('接收', '失败'), encoding='utf-8')
    with pytest.raises(ValueError, match='statement_conflict'):
        settlement.import_statement(db, statement)
