"""Record contract-output lifecycle observations and a simple freshness view."""
from datetime import datetime
from .store import connect

SCHEMA = """CREATE TABLE IF NOT EXISTS freshness_policy(
 id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL, sla_seconds INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS freshness_event(
 id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, output_id INTEGER NOT NULL,
 stage TEXT NOT NULL, occurred_at TEXT NOT NULL, observed_at TEXT NOT NULL,
 supersedes TEXT);
"""


def _instant(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone_required')
    return parsed


def policy(db_path, policy_id, contract_hash, sla_seconds):
    if not policy_id or not isinstance(sla_seconds, int) or isinstance(sla_seconds, bool) or sla_seconds <= 0:
        raise ValueError('invalid_freshness_policy')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (contract_hash,)).fetchone():
            raise ValueError('unknown_contract')
        with db:
            old = db.execute('SELECT contract_hash,sla_seconds FROM freshness_policy WHERE id=?',
                             (policy_id,)).fetchone()
            if old and (old['contract_hash'], old['sla_seconds']) != (contract_hash, sla_seconds):
                raise ValueError('freshness_policy_conflict')
            db.execute('INSERT OR IGNORE INTO freshness_policy VALUES (?,?,?)',
                       (policy_id, contract_hash, sla_seconds))
        return {'id': policy_id, 'contract_hash': contract_hash, 'sla_seconds': sla_seconds}
    finally:
        db.close()


def record(db_path, event_id, policy_id, output_id, stage, occurred_at, observed_at, supersedes=None):
    if not event_id or stage not in ('source', 'received', 'published'):
        raise ValueError('invalid_freshness_event')
    _instant(occurred_at)
    _instant(observed_at)
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        pol = db.execute('SELECT contract_hash FROM freshness_policy WHERE id=?', (policy_id,)).fetchone()
        if not pol:
            raise ValueError('unknown_freshness_policy')
        row = db.execute('''SELECT c.hash FROM output o JOIN run r ON r.id=o.run_id
                            JOIN contract c ON c.id=r.contract_id WHERE o.id=?''', (output_id,)).fetchone()
        if not row or row['hash'] != pol['contract_hash']:
            raise ValueError('output_contract_mismatch')
        payload = (policy_id, output_id, stage, occurred_at, observed_at, supersedes)
        with db:
            old = db.execute('SELECT policy_id,output_id,stage,occurred_at,observed_at,supersedes '
                             'FROM freshness_event WHERE id=?', (event_id,)).fetchone()
            if old and tuple(old) != payload:
                raise ValueError('freshness_event_conflict')
            db.execute('INSERT OR IGNORE INTO freshness_event VALUES (?,?,?,?,?,?,?)',
                       (event_id, *payload))
        return {'id': event_id}
    finally:
        db.close()


def report(db_path, policy_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        pol = db.execute('SELECT sla_seconds FROM freshness_policy WHERE id=?', (policy_id,)).fetchone()
        if not pol:
            raise ValueError('unknown_freshness_policy')
        grouped = {}
        for row in db.execute('SELECT * FROM freshness_event WHERE policy_id=? ORDER BY id', (policy_id,)):
            grouped.setdefault(row['output_id'], {}).setdefault(row['stage'], row['occurred_at'])
        items = []
        for output_id, stages in sorted(grouped.items()):
            if 'source' not in stages or 'published' not in stages:
                status, elapsed = '待核', None
            else:
                elapsed = (_instant(stages['published']) - _instant(stages['source'])).total_seconds()
                status = '达标' if 0 <= elapsed <= pol['sla_seconds'] else '超时'
            items.append({'output_id': output_id, 'elapsed_seconds': elapsed, 'status': status})
        return {'policy_id': policy_id, 'items': items}
    finally:
        db.close()
