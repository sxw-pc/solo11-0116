"""Compare translated cohorts before a consumer switches contract versions."""
import json
from .store import connect
from . import engine


def plan(path, plan_id, baseline_hash, target_hash, max_amount_delta):
    if not plan_id or baseline_hash == target_hash or max_amount_delta < 0:
        raise ValueError('invalid_migration_plan')
    db = connect(path)
    try:
        with db:
            for digest in (baseline_hash, target_hash):
                if not db.execute('SELECT 1 FROM contract WHERE hash=?', (digest,)).fetchone():
                    raise ValueError('unknown_contract')
            old = db.execute('SELECT * FROM migration_plan WHERE id=?', (plan_id,)).fetchone()
            if old and (old['baseline_hash'], old['target_hash'], old['max_amount_delta']) != (
                    baseline_hash, target_hash, max_amount_delta):
                raise ValueError('migration_identity_conflict')
            db.execute("INSERT OR IGNORE INTO migration_plan VALUES (?,?,?,?, '未对照','not_compared')",
                       (plan_id, baseline_hash, target_hash, max_amount_delta))
    finally:
        db.close()


def compare(path, plan_id):
    db = connect(path)
    try:
        plan_row = db.execute('SELECT * FROM migration_plan WHERE id=?', (plan_id,)).fetchone()
        if not plan_row:
            raise ValueError('unknown_migration_plan')
        old_verified = {x['id']: x for x in engine.verify(path, plan_row['baseline_hash'])}
        new_verified = {x['id']: x for x in engine.verify(path, plan_row['target_hash'])}
        def outputs(digest):
            return {r['envelope_id']: dict(r) for r in db.execute('''SELECT o.* FROM output o
                JOIN run r ON r.id=o.run_id JOIN contract c ON c.id=r.contract_id
                WHERE c.hash=?''', (digest,))}
        old, new = outputs(plan_row['baseline_hash']), outputs(plan_row['target_hash'])
        diffs = []
        for envelope_id in sorted(set(old) | set(new)):
            before, after = old.get(envelope_id), new.get(envelope_id)
            delta = None
            if not before or not after:
                status, reason = '待核', 'missing_side'
            elif (old_verified[before['id']]['status'] != '已核验' or
                  new_verified[after['id']]['status'] != '已核验'):
                status, reason = '待核', 'unverified_translation'
            else:
                old_body, new_body = json.loads(before['body']), json.loads(after['body'])
                if old_body.get('id') != new_body.get('id') or old_body.get('status') != new_body.get('status'):
                    status, reason = '阻断', 'identity_or_status_changed'
                elif not all(isinstance(x.get('amount'), (int, float)) and
                             not isinstance(x.get('amount'), bool) for x in (old_body, new_body)):
                    status, reason = '待核', 'amount_missing'
                else:
                    delta = new_body['amount'] - old_body['amount']
                    if abs(delta) > plan_row['max_amount_delta']:
                        status, reason = '阻断', 'amount_drift'
                    else:
                        status, reason = '兼容', 'within_delta'
            diffs.append({'envelope_id': envelope_id,
                          'baseline_output': before['id'] if before else None,
                          'target_output': after['id'] if after else None,
                          'amount_delta': delta, 'status': status, 'reason': reason})
        if not diffs or any(d['status'] == '待核' for d in diffs):
            status, reason = '待核', 'incomplete_evidence'
        elif any(d['status'] == '阻断' for d in diffs):
            status, reason = '阻断', 'semantic_drift'
        else:
            status, reason = '可切换', 'cohort_compatible'
        with db:
            db.execute('DELETE FROM migration_diff WHERE plan_id=?', (plan_id,))
            for d in diffs:
                db.execute('INSERT INTO migration_diff VALUES (?,?,?,?,?,?,?)',
                           (plan_id, d['envelope_id'], d['baseline_output'], d['target_output'],
                            d['amount_delta'], d['status'], d['reason']))
            db.execute('UPDATE migration_plan SET status=?,reason=? WHERE id=?',
                       (status, reason, plan_id))
        return {'status': status, 'reason': reason, 'diffs': diffs}
    finally:
        db.close()
