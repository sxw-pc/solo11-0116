import json
import pytest
from contractbridge import engine, freshness


def test_frozen_freshness_observations(tmp_path):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id'], 'rules': [{'target': 'id', 'source': '/entity_id'}]}
    db = tmp_path / 'ledger.db'
    digest = engine.freeze(db, contract)
    source = tmp_path / 'source.jsonl'
    source.write_text(json.dumps({'version': 'v1', 'entity_id': 'A', 'subject': 'S', 'legacy': {}}))
    engine.ingest(db, source, contract)
    output_id = engine.translate(db, digest)[0]
    freshness.policy(db, 'p1', digest, 300)
    observations = [('src', 'source', '2026-01-01T00:00:00Z'),
                    ('recv', 'received', '2026-01-01T00:09:00Z'),
                    ('pub', 'published', '2026-01-01T00:10:00Z')]
    for event_id, stage, occurred in observations:
        assert freshness.record(db, event_id, 'p1', output_id, stage, occurred,
                                '2026-01-01T00:11:00Z') == {'id': event_id}
    assert freshness.report(db, 'p1')['items'][0]['status'] == '超时'
    with pytest.raises(ValueError, match='freshness_event_conflict'):
        freshness.record(db, 'pub', 'p1', output_id, 'published', '2026-01-01T00:01:00Z',
                         '2026-01-01T00:11:00Z')
