"""Consumer exposure allocation and replayable delivery receipts."""
import json
from .store import connect
from . import engine


def policy(db_path, consumer, contract_hash, amount_limit):
    if not consumer or amount_limit < 0:
        raise ValueError('invalid_consumer_policy')
    db = connect(db_path)
    try:
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (contract_hash,)).fetchone():
            raise ValueError('unknown_contract')
        old = db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone()
        if old and (old['contract_hash'], old['amount_limit']) != (contract_hash, amount_limit):
            raise ValueError('policy_is_immutable')
        with db:
            db.execute('INSERT OR IGNORE INTO consumer_policy(consumer,contract_hash,amount_limit) VALUES (?,?,?)',
                       (consumer, contract_hash, amount_limit))
        return dict(db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone())
    finally:
        db.close()


def allocate(db_path, consumer):
    db = connect(db_path)
    try:
        pol = db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone()
        if not pol:
            raise ValueError('unknown_consumer')
        verified = {x['id']: x for x in engine.verify(db_path, pol['contract_hash'])}
        rows = [dict(x) for x in db.execute('''SELECT o.*,e.entity_id,c.hash AS contract_hash
            FROM output o JOIN envelope e ON e.id=o.envelope_id
            JOIN run r ON r.id=o.run_id JOIN contract c ON c.id=r.contract_id
            WHERE c.hash=? ORDER BY o.id''', (pol['contract_hash'],))]
        counts = {}
        for row in rows:
            counts[row['entity_id']] = counts.get(row['entity_id'], 0) + 1
        used = 0
        results = []
        with db:
            for row in rows:
                body = json.loads(row['body'])
                amount = body.get('amount')
                if verified[row['id']]['status'] != '已核验':
                    status, reason = '待核', 'output_unverified'
                elif counts[row['entity_id']] > 1:
                    status, reason = '待核', 'duplicate_entity'
                elif not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount < 0 or int(amount) != amount:
                    status, reason = '待核', 'amount_invalid'
                elif used + amount > pol['amount_limit']:
                    status, reason = '拒配', 'limit_exceeded'
                else:
                    status, reason = '已配额', 'within_limit'
                    used += amount
                db.execute('''INSERT INTO allocation(consumer,contract_hash,output_id,status,reason)
                    VALUES (?,?,?,?,?) ON CONFLICT(consumer,output_id) DO UPDATE SET
                    status=excluded.status,reason=excluded.reason''',
                    (consumer, pol['contract_hash'], row['id'], status, reason))
                results.append({'output_id': row['id'], 'status': status, 'reason': reason})
        return {'consumer': consumer, 'used': used, 'limit': pol['amount_limit'], 'items': results}
    finally:
        db.close()


def dispatch(db_path, consumer):
    allocation = allocate(db_path, consumer)
    db = connect(db_path)
    try:
        pol = db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone()
        old = db.execute('SELECT * FROM delivery WHERE consumer=? AND contract_hash=?',
                         (consumer, pol['contract_hash'])).fetchone()
        if old:
            return delivery_status(db_path, old['id'])
        if not allocation['items'] or any(x['status'] != '已配额' for x in allocation['items']):
            status = '暂缓'
        else:
            status = '待回执'
        with db:
            did = db.execute('INSERT INTO delivery(consumer,contract_hash,status) VALUES (?,?,?)',
                             (consumer, pol['contract_hash'], status)).lastrowid
            if status == '待回执':
                for item in allocation['items']:
                    row = db.execute('SELECT hash FROM output WHERE id=?', (item['output_id'],)).fetchone()
                    db.execute('INSERT INTO delivery_item VALUES (?,?,?,?)',
                               (did, item['output_id'], row['hash'], '待回执'))
        return delivery_status(db_path, did)
    finally:
        db.close()


def acknowledge(db_path, delivery_id, output_id, output_hash, result):
    if result not in ('接收', '失败'):
        raise ValueError('invalid_ack_result')
    db = connect(db_path)
    try:
        item = db.execute('SELECT * FROM delivery_item WHERE delivery_id=? AND output_id=?',
                          (delivery_id, output_id)).fetchone()
        if not item or item['hash'] != output_hash:
            raise ValueError('delivery_item_mismatch')
        old = db.execute('SELECT * FROM delivery_ack WHERE delivery_id=? AND output_id=?',
                         (delivery_id, output_id)).fetchone()
        if old and (old['hash'], old['result']) != (output_hash, result):
            raise ValueError('ack_conflict')
        with db:
            db.execute('INSERT OR IGNORE INTO delivery_ack(delivery_id,output_id,hash,result) VALUES (?,?,?,?)',
                       (delivery_id, output_id, output_hash, result))
            db.execute('UPDATE delivery_item SET status=? WHERE delivery_id=? AND output_id=?',
                       (result, delivery_id, output_id))
            statuses = [x['status'] for x in db.execute('SELECT status FROM delivery_item WHERE delivery_id=?',
                                                       (delivery_id,))]
            overall = ('已交付' if all(x == '接收' for x in statuses) else
                       '部分失败' if '失败' in statuses else '待回执')
            db.execute('UPDATE delivery SET status=? WHERE id=?', (overall, delivery_id))
        return delivery_status(db_path, delivery_id)
    finally:
        db.close()


def delivery_status(db_path, delivery_id):
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM delivery WHERE id=?', (delivery_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery')
        result = dict(row)
        result['items'] = [dict(x) for x in db.execute(
            'SELECT output_id,hash,status FROM delivery_item WHERE delivery_id=? ORDER BY output_id',
            (delivery_id,))]
        return result
    finally:
        db.close()
