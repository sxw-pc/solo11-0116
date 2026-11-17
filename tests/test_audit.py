import json
import pytest
from contractbridge import audit, engine


def test_frozen_audit_scope(tmp_path):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id'], 'rules': [{'target': 'id', 'source': '/entity_id'}]}
    db = tmp_path / 'ledger.db'
    contract_hash = engine.freeze(db, contract)
    source = tmp_path / 'source.jsonl'
    source.write_text(json.dumps({'version': 'v1', 'entity_id': 'A', 'subject': 'S', 'legacy': {}}))
    engine.ingest(db, source, contract)
    engine.translate(db, contract_hash)
    first = audit.request(db, 'audit-1', contract_hash, [1], 'regulatory-review')
    assert audit.request(db, 'audit-1', contract_hash, [1], 'regulatory-review') == first
    assert audit.describe(db, 'audit-1')['source_ids'] == [1]
    with pytest.raises(ValueError, match='audit_request_conflict'):
        audit.request(db, 'audit-1', contract_hash, [1], 'different-purpose')
