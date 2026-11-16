import json
import pytest
from contractbridge import engine, operations
from contractbridge.store import connect


def setup_case(tmp_path, amounts):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id', 'amount'],
                'rules': [{'target': 'id', 'source': '/entity_id'},
                          {'target': 'amount', 'source': '/legacy/value', 'op': 'scale', 'factor': 100}],
                'errors': {}}
    db = tmp_path / 'db'
    contract_hash = engine.freeze(db, contract)
    source = tmp_path / 'source.jsonl'
    source.write_text('\n'.join(json.dumps({'version': 'v1', 'entity_id': f'E-{i}',
                                           'subject': f'Subject {i}', 'legacy': {'value': value}})
                                for i, value in enumerate(amounts)), encoding='utf-8')
    engine.ingest(db, source, contract)
    engine.translate(db, contract_hash)
    return db, contract_hash


def test_exposure_allocation_changes_delivery_decision(tmp_path):
    db, h = setup_case(tmp_path, [2, 3])
    operations.policy(db, 'small', h, 400)
    result = operations.allocate(db, 'small')
    assert [x['status'] for x in result['items']] == ['已配额', '拒配']
    assert result['used'] == 200
    assert operations.dispatch(db, 'small')['status'] == '暂缓'
    operations.policy(db, 'large', h, 500)
    delivery = operations.dispatch(db, 'large')
    assert delivery['status'] == '待回执' and len(delivery['items']) == 2
    with pytest.raises(ValueError, match='policy_is_immutable'):
        operations.policy(db, 'large', h, 600)


def test_partial_delivery_and_conflicting_ack(tmp_path):
    db, h = setup_case(tmp_path, [1, 2])
    operations.policy(db, 'c', h, 500)
    delivery = operations.dispatch(db, 'c')
    assert operations.dispatch(db, 'c')['id'] == delivery['id']
    first, second = delivery['items']
    result = operations.acknowledge(db, delivery['id'], first['output_id'], first['hash'], '接收')
    assert result['status'] == '待回执'
    result = operations.acknowledge(db, delivery['id'], second['output_id'], second['hash'], '失败')
    assert result['status'] == '部分失败'
    assert operations.acknowledge(db, delivery['id'], second['output_id'], second['hash'], '失败')['status'] == '部分失败'
    with pytest.raises(ValueError, match='ack_conflict'):
        operations.acknowledge(db, delivery['id'], second['output_id'], second['hash'], '接收')
    with pytest.raises(ValueError, match='delivery_item_mismatch'):
        operations.acknowledge(db, delivery['id'], first['output_id'], 'wrong', '接收')


def test_tampered_translation_cannot_be_allocated(tmp_path):
    db, h = setup_case(tmp_path, [1])
    with connect(db) as conn:
        conn.execute("UPDATE output SET body='{}'")
    operations.policy(db, 'c', h, 1000)
    allocation = operations.allocate(db, 'c')
    assert allocation['items'][0]['reason'] == 'output_unverified'
    assert operations.dispatch(db, 'c')['status'] == '暂缓'
