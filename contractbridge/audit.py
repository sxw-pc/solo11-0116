"""Freeze an auditor's requested evidence scope before issuing a package."""
import hashlib
import json
from .store import connect

SCHEMA = """CREATE TABLE IF NOT EXISTS audit_request(
    id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL,
    source_ids TEXT NOT NULL, purpose TEXT NOT NULL,
    request_sha TEXT NOT NULL);
"""


def request(db_path, request_id, contract_hash, source_ids, purpose):
    if (not request_id or not contract_hash or not purpose or
            not isinstance(source_ids, list) or not source_ids or
            any(not isinstance(x, int) or isinstance(x, bool) or x <= 0 for x in source_ids) or
            len(set(source_ids)) != len(source_ids)):
        raise ValueError('invalid_audit_request')
    source_ids = sorted(source_ids)
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (contract_hash,)).fetchone():
            raise ValueError('unknown_contract')
        for source_id in source_ids:
            if not db.execute('SELECT 1 FROM source WHERE id=?', (source_id,)).fetchone():
                raise ValueError('unknown_source')
        body = json.dumps({'id': request_id, 'contract_hash': contract_hash,
                           'source_ids': source_ids, 'purpose': purpose},
                          ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(body.encode()).hexdigest()
        with db:
            old = db.execute('SELECT request_sha FROM audit_request WHERE id=?', (request_id,)).fetchone()
            if old and old['request_sha'] != digest:
                raise ValueError('audit_request_conflict')
            db.execute('INSERT OR IGNORE INTO audit_request VALUES (?,?,?,?,?)',
                       (request_id, contract_hash, json.dumps(source_ids), purpose, digest))
        return {'id': request_id, 'request_sha': digest}
    finally:
        db.close()


def describe(db_path, request_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM audit_request WHERE id=?', (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_audit_request')
        item = dict(row)
        item['source_ids'] = json.loads(item['source_ids'])
        return item
    finally:
        db.close()
