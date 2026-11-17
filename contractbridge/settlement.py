"""Import a consumer statement and perform a first-pass delivery match."""
import hashlib
import json
from pathlib import Path
from .store import connect

SCHEMA = """CREATE TABLE IF NOT EXISTS settlement_statement(
 id TEXT PRIMARY KEY, delivery_id INTEGER NOT NULL, raw BLOB NOT NULL, raw_sha TEXT NOT NULL);
"""


def import_statement(db_path, statement_path):
    raw = Path(statement_path).read_bytes()
    item = json.loads(raw)
    if not isinstance(item, dict) or not item.get('id') or not isinstance(item.get('delivery_id'), int):
        raise ValueError('invalid_statement')
    lines = item.get('lines')
    if not isinstance(lines, list) or not lines or len({x.get('line_id') for x in lines}) != len(lines):
        raise ValueError('invalid_statement_lines')
    for line in lines:
        if (not line.get('line_id') or not isinstance(line.get('hash_prefix'), str) or
                line.get('result') not in ('接收', '失败')):
            raise ValueError('invalid_statement_line')
    digest = hashlib.sha256(raw).hexdigest()
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM delivery WHERE id=?', (item['delivery_id'],)).fetchone():
            raise ValueError('unknown_delivery')
        with db:
            old = db.execute('SELECT raw_sha FROM settlement_statement WHERE id=?', (item['id'],)).fetchone()
            if old and old['raw_sha'] != digest:
                raise ValueError('statement_conflict')
            db.execute('INSERT OR IGNORE INTO settlement_statement VALUES (?,?,?,?)',
                       (item['id'], item['delivery_id'], raw, digest))
        return {'id': item['id'], 'raw_sha': digest}
    finally:
        db.close()


def reconcile(db_path, statement_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM settlement_statement WHERE id=?', (statement_id,)).fetchone()
        if not row:
            raise ValueError('unknown_statement')
        item = json.loads(row['raw'])
        delivery_items = [dict(x) for x in db.execute('''SELECT di.output_id,di.hash,o.body
            FROM delivery_item di JOIN output o ON o.id=di.output_id
            WHERE di.delivery_id=? ORDER BY di.output_id''', (row['delivery_id'],))]
        used = set()
        matched = []
        for line in item['lines']:
            found = None
            for target in delivery_items:
                if target['output_id'] in used or not target['hash'].startswith(line['hash_prefix']):
                    continue
                if 'amount' in line and json.loads(target['body']).get('amount') != line['amount']:
                    continue
                found = target['output_id']
                used.add(found)
                break
            matched.append({'line_id': line['line_id'], 'output_id': found, 'result': line['result']})
        return {'statement_id': statement_id,
                'status': '已匹配' if len(used) == len(delivery_items) == len(matched) and
                all(x['output_id'] is not None for x in matched) else '待核',
                'items': matched}
    finally:
        db.close()
