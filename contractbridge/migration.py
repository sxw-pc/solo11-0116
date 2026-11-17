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


def resolve_entity(declarations, id_text, instant):
    """Resolve an output id text to its real entity under the frozen declarations."""
    matches = declarations.get(id_text, [])
    if not matches:
        return id_text
    if instant is None:
        return None
    status, chosen = engine.covering_declaration(matches, instant)
    if status == 'attributed':
        return chosen['stable_id']
    if status == 'held':
        return None
    return id_text


def compare(path, plan_id):
    db = connect(path)
    try:
        plan_row = db.execute('SELECT * FROM migration_plan WHERE id=?', (plan_id,)).fetchone()
        if not plan_row:
            raise ValueError('unknown_migration_plan')
        old_verified = {x['id']: x for x in engine.verify(path, plan_row['baseline_hash'])}
        new_verified = {x['id']: x for x in engine.verify(path, plan_row['target_hash'])}
        def outputs(digest):
            rows = db.execute('''SELECT o.* FROM output o
                JOIN run r ON r.id=o.run_id JOIN contract c ON c.id=r.contract_id
                WHERE c.hash=? ORDER BY o.id''', (digest,))
            result = {}
            for row in rows:
                result[row['envelope_id']] = dict(row)
            return result
        old, new = outputs(plan_row['baseline_hash']), outputs(plan_row['target_hash'])
        with db:
            bridge_version = engine.current_bridge_version(db)
            declarations = {}
            for d in db.execute('SELECT * FROM bridge_declaration'):
                declarations.setdefault(d['legacy_key'], []).append(dict(d))
            envelopes = {r['id']: dict(r) for r in db.execute('SELECT id,raw FROM envelope')}
            attributions = {(r['run_id'], r['envelope_id']): dict(r)
                            for r in db.execute('SELECT * FROM attribution')}
            def side_instant(output, envelope_id):
                attribution = attributions.get((output['run_id'], envelope_id))
                if attribution and attribution['instant']:
                    return engine.try_instant(attribution['instant'])
                raw = envelopes.get(envelope_id, {}).get('raw')
                return engine.try_instant(json.loads(raw).get('event_time')) if raw else None
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
                    old_id, new_id = old_body.get('id'), new_body.get('id')
                    if old_id == new_id:
                        entity_verdict = 'same'
                    else:
                        old_entity = resolve_entity(declarations, old_id, side_instant(before, envelope_id))
                        new_entity = resolve_entity(declarations, new_id, side_instant(after, envelope_id))
                        if old_entity is None or new_entity is None:
                            entity_verdict = 'held'
                        elif old_entity != new_entity:
                            entity_verdict = 'drift'
                        else:
                            entity_verdict = 'same'
                    if entity_verdict == 'held':
                        status, reason = '待核', 'identity_attribution_held'
                    elif entity_verdict == 'drift':
                        status, reason = '阻断', 'subject_drift'
                    elif old_body.get('status') != new_body.get('status'):
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
            db.execute('DELETE FROM migration_diff WHERE plan_id=? AND bridge_version=?', (plan_id, bridge_version))
            for d in diffs:
                db.execute('INSERT INTO migration_diff VALUES (?,?,?,?,?,?,?,?)',
                           (plan_id, d['envelope_id'], bridge_version, d['baseline_output'], d['target_output'],
                            d['amount_delta'], d['status'], d['reason']))
            db.execute('INSERT OR REPLACE INTO migration_compare(plan_id,bridge_version,status,reason) VALUES (?,?,?,?)',
                       (plan_id, bridge_version, status, reason))
            db.execute('UPDATE migration_plan SET status=?,reason=? WHERE id=?',
                       (status, reason, plan_id))
        return {'status': status, 'reason': reason, 'bridge_version': bridge_version, 'diffs': diffs}
    finally:
        db.close()
