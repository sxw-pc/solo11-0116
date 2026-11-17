"""Consumer exposure allocation, permission-routed delivery and replayable receipts."""
import json
from .store import connect
from . import engine
from . import permissions


def _policy_view(row):
    return {'consumer': row['consumer'], 'contract_hash': row['contract_hash'],
            'amount_limit': row['amount_limit'],
            'allowed_labels': json.loads(row['allowed_labels']),
            'allowed_purposes': json.loads(row['allowed_purposes']),
            'route': row['route']}


def _evidence_of(db, output_id):
    return [(x['field'], x['pointer'], x['rule']) for x in db.execute(
        'SELECT field,pointer,rule FROM evidence WHERE output_id=?', (output_id,))]


def policy(db_path, consumer, contract_hash, amount_limit,
           allowed_labels=None, allowed_purposes=None, route='reject_envelope'):
    """Freeze a consumer policy: contract, quota, allowed labels/purposes, route."""
    if not consumer or amount_limit < 0 or route not in permissions.ROUTES:
        raise ValueError('invalid_consumer_policy')
    labels = sorted({str(x) for x in (allowed_labels or ())})
    purposes = sorted({str(x) for x in (allowed_purposes or ())})
    db = connect(db_path)
    try:
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (contract_hash,)).fetchone():
            raise ValueError('unknown_contract')
        old = db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone()
        if old and (old['contract_hash'], old['amount_limit'], json.loads(old['allowed_labels']),
                    json.loads(old['allowed_purposes']), old['route']) != (
                    contract_hash, amount_limit, labels, purposes, route):
            raise ValueError('policy_is_immutable')
        with db:
            db.execute('''INSERT OR IGNORE INTO consumer_policy
                (consumer,contract_hash,amount_limit,allowed_labels,allowed_purposes,route)
                VALUES (?,?,?,?,?,?)''',
                       (consumer, contract_hash, amount_limit, json.dumps(labels, ensure_ascii=False),
                        json.dumps(purposes, ensure_ascii=False), route))
        return _policy_view(db.execute('SELECT * FROM consumer_policy WHERE consumer=?',
                                       (consumer,)).fetchone())
    finally:
        db.close()


def allocate(db_path, consumer):
    """Merge per-item verification, source-permission adjudication, subject
    dedup and amount quota into one replayable allocation decision."""
    db = connect(db_path)
    try:
        pol_row = db.execute('SELECT * FROM consumer_policy WHERE consumer=?', (consumer,)).fetchone()
        if not pol_row:
            raise ValueError('unknown_consumer')
        pol = _policy_view(pol_row)
        contract = json.loads(db.execute('SELECT body FROM contract WHERE hash=?',
                                         (pol['contract_hash'],)).fetchone()['body'])
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
                verdict = permissions.adjudicate(contract, body, _evidence_of(db, row['id']), pol)
                redacted = json.dumps(verdict['redacted'], ensure_ascii=False)
                if verified[row['id']]['status'] != '已核验':
                    status, reason = '待核', 'output_unverified'
                elif verdict['decision'] == 'hold':
                    status, reason = '待核', verdict['reason']
                elif counts[row['entity_id']] > 1:
                    status, reason = '待核', 'duplicate_entity'
                elif not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount < 0 or int(amount) != amount:
                    status, reason = '待核', 'amount_invalid'
                elif used + amount > pol['amount_limit']:
                    status, reason = '拒配', 'limit_exceeded'
                else:
                    status, reason = '已配额', 'within_limit'
                    used += amount
                db.execute('''INSERT INTO allocation(consumer,contract_hash,output_id,status,reason,permission,redacted)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(consumer,output_id) DO UPDATE SET
                    status=excluded.status,reason=excluded.reason,
                    permission=excluded.permission,redacted=excluded.redacted''',
                           (consumer, pol['contract_hash'], row['id'], status, reason,
                            verdict['decision'], redacted))
                results.append({'output_id': row['id'], 'status': status, 'reason': reason,
                                'permission': verdict['decision'], 'redacted': verdict['redacted']})
        return {'consumer': consumer, 'used': used, 'limit': pol['amount_limit'], 'items': results}
    finally:
        db.close()


def dispatch(db_path, consumer):
    """Freeze the consumer-visible projection and its digest per allocated output."""
    from . import migration
    check = connect(db_path)
    try:
        consumer_policy = check.execute('SELECT * FROM consumer_policy WHERE consumer=?',
                                        (consumer,)).fetchone()
        if not consumer_policy:
            raise ValueError('unknown_consumer')
        pol = _policy_view(consumer_policy)
        contract = json.loads(check.execute('SELECT body FROM contract WHERE hash=?',
                                            (pol['contract_hash'],)).fetchone()['body'])
        plans = [x['id'] for x in check.execute('SELECT id FROM migration_plan WHERE target_hash=?',
                                                (pol['contract_hash'],))]
    finally:
        check.close()
    migration_statuses = [migration.compare(db_path, plan_id)['status'] for plan_id in plans]
    allocation = allocate(db_path, consumer)
    db = connect(db_path)
    try:
        old = db.execute('SELECT * FROM delivery WHERE consumer=? AND contract_hash=?',
                         (consumer, pol['contract_hash'])).fetchone()
        if old:
            return delivery_status(db_path, old['id'])
        blocked = (not allocation['items'] or
                   any(x['status'] != '已配额' for x in allocation['items']) or
                   any(x != '可切换' for x in migration_statuses))
        projections = []
        if not blocked:
            for item in allocation['items']:
                row = db.execute('SELECT body FROM output WHERE id=?', (item['output_id'],)).fetchone()
                verdict = permissions.adjudicate(contract, json.loads(row['body']),
                                                 _evidence_of(db, item['output_id']), pol)
                if verdict['decision'] == 'hold':
                    blocked = True
                    break
                projections.append((item['output_id'], verdict))
        status = '暂缓' if blocked else '待回执'
        reg = permissions.regime(contract)
        with db:
            did = db.execute('''INSERT INTO delivery(consumer,contract_hash,status,permission_version,route)
                VALUES (?,?,?,?,?)''',
                             (consumer, pol['contract_hash'], status,
                              reg['version'] if reg else None, pol['route'])).lastrowid
            if status == '待回执':
                for output_id, verdict in projections:
                    projection = engine.canonical(verdict['projection'])
                    db.execute('INSERT INTO delivery_item VALUES (?,?,?,?,?,?)',
                               (did, output_id, engine.sha(projection.encode()), '待回执',
                                projection, json.dumps(verdict['redacted'], ensure_ascii=False)))
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


def verify_delivery(db_path, delivery_id):
    """Independently re-derive permission propagation from raw envelopes and the
    frozen contract, and compare with the frozen delivery projections."""
    db = connect(db_path)
    try:
        delivery = db.execute('SELECT * FROM delivery WHERE id=?', (delivery_id,)).fetchone()
        if not delivery:
            raise ValueError('unknown_delivery')
        pol = _policy_view(db.execute('SELECT * FROM consumer_policy WHERE consumer=?',
                                      (delivery['consumer'],)).fetchone())
        contract = json.loads(db.execute('SELECT body FROM contract WHERE hash=?',
                                         (delivery['contract_hash'],)).fetchone()['body'])
        items = []
        for item in db.execute('SELECT * FROM delivery_item WHERE delivery_id=? ORDER BY output_id',
                               (delivery_id,)):
            codes = []
            row = db.execute('''SELECT o.*,e.raw AS envelope_raw,e.entity_id AS entity_id,
                c.hash AS output_contract FROM output o JOIN envelope e ON e.id=o.envelope_id
                JOIN run r ON r.id=o.run_id JOIN contract c ON c.id=r.contract_id
                WHERE o.id=?''', (item['output_id'],)).fetchone()
            if row is None:
                codes.append('output_missing')
            else:
                if row['output_contract'] != delivery['contract_hash']:
                    codes.append('contract_mismatch')
                source = json.loads(row['envelope_raw'])
                source['entity_id'] = row['entity_id']
                expected, expected_evidence, _ = engine.transform(source, contract)
                if engine.canonical(expected) != row['body']:
                    codes.append('business_mismatch')
                stored = {(x['field'], x['pointer'], x['rule']) for x in db.execute(
                    'SELECT field,pointer,rule FROM evidence WHERE output_id=?', (item['output_id'],))}
                if stored != set(expected_evidence):
                    codes.append('evidence_mismatch')
                verdict = permissions.adjudicate(contract, expected, expected_evidence, pol)
                if verdict['decision'] == 'hold':
                    codes.append('permission_hold_delivered')
                else:
                    projection = engine.canonical(verdict['projection'])
                    expected_hash = engine.sha(projection.encode())
                    stored_hash = None
                    if item['projection'] is not None:
                        try:
                            stored_hash = engine.sha(engine.canonical(
                                json.loads(item['projection'])).encode())
                        except json.JSONDecodeError:
                            stored_hash = None
                    if item['projection'] != projection:
                        codes.append('projection_mismatch')
                    if item['hash'] != expected_hash or stored_hash != expected_hash:
                        codes.append('projection_hash')
                    if json.loads(item['redacted']) != verdict['redacted']:
                        codes.append('redaction_mismatch')
            items.append({'output_id': item['output_id'],
                          'status': '拒绝' if codes else '已核验', 'issues': codes})
        return {'delivery_id': delivery_id, 'consumer': delivery['consumer'],
                'status': '拒绝' if any(x['issues'] for x in items) else delivery['status'],
                'items': items}
    finally:
        db.close()


def delivery_status(db_path, delivery_id):
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM delivery WHERE id=?', (delivery_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery')
        result = dict(row)
        result['items'] = []
        for item in db.execute(
                'SELECT output_id,hash,status,projection,redacted FROM delivery_item '
                'WHERE delivery_id=? ORDER BY output_id', (delivery_id,)):
            entry = {'output_id': item['output_id'], 'hash': item['hash'], 'status': item['status'],
                     'redacted': json.loads(item['redacted'])}
            if item['projection'] is not None:
                entry['projection'] = json.loads(item['projection'])
            result['items'].append(entry)
        return result
    finally:
        db.close()
