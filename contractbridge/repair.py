"""Freeze a bounded operator repair case without changing source envelopes."""
import hashlib
import json
from .store import connect

SCHEMA = """CREATE TABLE IF NOT EXISTS repair_case(
    id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL, body TEXT NOT NULL,
    input_digest TEXT NOT NULL);
"""


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def open_case(db_path, case):
    if not isinstance(case, dict) or not case.get('id') or not case.get('contract_hash'):
        raise ValueError('invalid_repair_case')
    envelope_ids = case.get('envelope_ids')
    proposals = case.get('proposals')
    if (not isinstance(envelope_ids, list) or not envelope_ids or
            any(not isinstance(x, int) or isinstance(x, bool) for x in envelope_ids) or
            len(set(envelope_ids)) != len(envelope_ids) or
            not isinstance(proposals, list) or not proposals):
        raise ValueError('invalid_repair_scope')
    seen = set()
    for proposal in proposals:
        if (not isinstance(proposal, dict) or proposal.get('envelope_id') not in envelope_ids or
                not isinstance(proposal.get('path'), str) or not proposal['path'].startswith('/') or
                not isinstance(proposal.get('cost'), int) or isinstance(proposal['cost'], bool) or
                proposal['cost'] <= 0 or 'value' not in proposal):
            raise ValueError('invalid_repair_proposal')
        key = (proposal['envelope_id'], proposal['path'])
        if key in seen:
            raise ValueError('duplicate_repair_target')
        seen.add(key)
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (case['contract_hash'],)).fetchone():
            raise ValueError('unknown_contract')
        snapshot = []
        for eid in sorted(envelope_ids):
            row = db.execute('''SELECT e.raw,s.hash AS source_hash FROM envelope e
                                JOIN source s ON s.id=e.source_id WHERE e.id=?''', (eid,)).fetchone()
            if not row:
                raise ValueError('unknown_envelope')
            snapshot.append((eid, row['source_hash'], hashlib.sha256(row['raw'].encode()).hexdigest()))
        digest = hashlib.sha256(_canonical(snapshot).encode()).hexdigest()
        body = _canonical(case)
        with db:
            old = db.execute('SELECT body,input_digest FROM repair_case WHERE id=?', (case['id'],)).fetchone()
            if old and (old['body'], old['input_digest']) != (body, digest):
                raise ValueError('repair_case_conflict')
            db.execute('INSERT OR IGNORE INTO repair_case VALUES (?,?,?,?)',
                       (case['id'], case['contract_hash'], body, digest))
        return {'id': case['id'], 'input_digest': digest}
    finally:
        db.close()


def describe(db_path, case_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT body,input_digest FROM repair_case WHERE id=?', (case_id,)).fetchone()
        if not row:
            raise ValueError('unknown_repair_case')
        return {'case': json.loads(row['body']), 'input_digest': row['input_digest']}
    finally:
        db.close()
