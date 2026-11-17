import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from contractbridge import engine, migration, operations, permissions
from contractbridge.store import connect

ROOT = Path(__file__).resolve().parents[1]

PUBLIC = {'allowed_labels': ['public'],
          'allowed_purposes': ['identification', 'billing', 'status']}
FULL = {'allowed_labels': ['public', 'restricted'],
        'allowed_purposes': ['identification', 'billing', 'status', 'risk_scoring']}


def perm_contract(required=('id',), extra_rules=(), labels=None, version='p1', target_version='v2'):
    return {
        'versions': [{'version': 'v1', 'signature': ['/legacy']},
                     {'version': target_version, 'signature': ['/new']}],
        'required': list(required),
        'rules': [
            {'target': 'id', 'source': '/entity_id'},
            {'target': 'amount', 'source': '/legacy/value', 'op': 'scale', 'factor': 100},
            {'target': 'score', 'source': '/profile/private_score', 'op': 'scale', 'factor': 100},
            {'target': 'score_label', 'source': '$score', 'op': 'chain'},
            *extra_rules,
        ],
        'errors': {},
        'permission_version': version,
        'source_permissions': labels if labels is not None else {
            '/entity_id': {'label': 'public', 'purpose': 'identification'},
            '/legacy/value': {'label': 'public', 'purpose': 'billing'},
            '/status': {'label': 'public', 'purpose': 'status'},
            '/profile/private_score': {'label': 'restricted', 'purpose': 'risk_scoring'},
        },
    }


def envelope(entity='A', value=2, **over):
    base = {'version': 'v1', 'entity_id': entity, 'subject': f'Subject {entity}',
            'legacy': {'value': value}, 'profile': {'private_score': 0.5}, 'status': 'ok'}
    base.update(over)
    return base


def setup_case(tmp_path, contract, envelopes, name='db'):
    db = tmp_path / name
    contract_hash = engine.freeze(db, contract)
    source = tmp_path / f'{name}.jsonl'
    source.write_text('\n'.join(json.dumps(e) for e in envelopes), encoding='utf-8')
    engine.ingest(db, source, contract)
    engine.translate(db, contract_hash)
    return db, contract_hash


def test_chain_inherits_all_source_permissions():
    contract = perm_contract()
    out, evidence, issues = engine.transform(envelope(), contract)
    assert not issues
    verdict = permissions.adjudicate(contract, out, evidence,
                                     {**PUBLIC, 'route': 'reject_envelope'})
    assert verdict['decision'] == 'hold'
    assert verdict['restricted'] == ['score', 'score_label']
    assert verdict['atoms']['score_label'] == [('restricted', 'risk_scoring')]
    full = permissions.adjudicate(contract, out, evidence, {**FULL, 'route': 'reject_envelope'})
    assert full['decision'] == 'deliver'


def test_default_uses_synthetic_source_label():
    contract = perm_contract(extra_rules=[{'target': 'note', 'source': '/legacy/absent',
                                           'default': 'N/A'}])
    out, evidence, _ = engine.transform(envelope(), contract)
    assert out['note'] == 'N/A' and ('note', None, 'default') in evidence
    verdict = permissions.adjudicate(contract, out, evidence, {**PUBLIC, 'route': 'redact_optional'})
    assert verdict['decision'] == 'redact'
    assert verdict['redacted'] == ['note', 'score', 'score_label']
    synth = {'allowed_labels': ['public', 'synthetic'],
             'allowed_purposes': PUBLIC['allowed_purposes'] + ['contract_default'],
             'route': 'redact_optional'}
    verdict = permissions.adjudicate(contract, out, evidence, synth)
    assert 'note' not in verdict['restricted'] and verdict['projection']['note'] == 'N/A'


def test_unknown_source_is_never_public():
    labels = {k: v for k, v in perm_contract()['source_permissions'].items()
              if k != '/legacy/value'}
    contract = perm_contract(labels=labels)
    out, evidence, _ = engine.transform(envelope(), contract)
    sneaky = {'allowed_labels': ['public', 'unknown'],
              'allowed_purposes': ['identification', 'billing', 'status', 'unknown'],
              'route': 'reject_envelope'}
    verdict = permissions.adjudicate(contract, out, evidence, sneaky)
    assert verdict['decision'] == 'hold' and 'amount' in verdict['restricted']


def test_missing_evidence_is_not_public():
    contract = perm_contract()
    out, evidence, _ = engine.transform(envelope(), contract)
    trimmed = [row for row in evidence if row[0] != 'score']
    verdict = permissions.adjudicate(contract, out, trimmed, {**FULL, 'route': 'reject_envelope'})
    assert verdict['decision'] == 'hold'
    assert 'score' in verdict['restricted'] and 'score_label' in verdict['restricted']


def test_error_status_keeps_status_source_permission():
    contract = perm_contract()
    contract['errors'] = {'TEMP': 'retry'}
    contract['source_permissions']['/status'] = {'label': 'restricted', 'purpose': 'ops'}
    out, evidence, issues = engine.transform(envelope(status='TEMP'), contract)
    assert out['status'] == 'retry' and not issues
    verdict = permissions.adjudicate(contract, out, evidence, {**FULL, 'route': 'redact_optional'})
    assert verdict['decision'] == 'hold'
    assert verdict['reason'] == 'required_field_restricted' and 'status' in verdict['blocking']
    ops = {'allowed_labels': FULL['allowed_labels'],
           'allowed_purposes': FULL['allowed_purposes'] + ['ops'], 'route': 'redact_optional'}
    assert permissions.adjudicate(contract, out, evidence, ops)['decision'] == 'deliver'


def test_enum_and_copy_preserve_source_permission():
    contract = perm_contract(extra_rules=[
        {'target': 'score_band', 'source': '/profile/band', 'op': 'enum', 'values': {'1': 'low'}},
        {'target': 'score_copy', 'source': '/profile/other'}])
    contract['source_permissions']['/profile/band'] = {'label': 'restricted',
                                                       'purpose': 'risk_scoring'}
    env = envelope()
    env['profile']['band'] = 1
    env['profile']['other'] = 'x'
    out, evidence, _ = engine.transform(env, contract)
    assert out['score_band'] == 'low'
    verdict = permissions.adjudicate(contract, out, evidence, {**PUBLIC, 'route': 'reject_envelope'})
    assert 'score_band' in verdict['restricted']
    assert 'score_copy' in verdict['restricted']


def test_contract_without_permission_regime_delivers_everything():
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id'], 'rules': [{'target': 'id', 'source': '/entity_id'}],
                'errors': {}}
    out, evidence, _ = engine.transform({'entity_id': 'A'}, contract)
    verdict = permissions.adjudicate(contract, out, evidence,
                                     {'allowed_labels': [], 'allowed_purposes': [],
                                      'route': 'reject_envelope'})
    assert verdict['decision'] == 'deliver' and verdict['reason'] == 'permissions_not_configured'


def test_freeze_rejects_bad_permission_section(tmp_path):
    contract = perm_contract()
    contract['source_permissions']['/legacy/value'] = {'label': 'public'}
    with pytest.raises(ValueError, match='invalid_source_permissions'):
        engine.freeze(tmp_path / 'db', contract)


def test_counterexample_two_routes(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'rejecter', h, 1000, route='reject_envelope', **PUBLIC)
    held = operations.allocate(db, 'rejecter')
    item = held['items'][0]
    assert (item['status'], item['reason'], item['permission']) == (
        '待核', 'permission_restricted', 'hold')
    assert operations.dispatch(db, 'rejecter')['status'] == '暂缓'

    operations.policy(db, 'redactor', h, 1000, route='redact_optional', **PUBLIC)
    allocation = operations.allocate(db, 'redactor')
    assert allocation['items'][0]['status'] == '已配额'
    assert allocation['items'][0]['permission'] == 'redact'
    assert allocation['used'] == 200
    delivery = operations.dispatch(db, 'redactor')
    assert delivery['status'] == '待回执' and delivery['permission_version'] == 'p1'
    (item,) = delivery['items']
    assert item['redacted'] == ['score', 'score_label']
    assert item['projection'] == {'id': 'A', 'amount': 200.0, 'status': 'ok'}
    assert item['hash'] == engine.sha(engine.canonical(item['projection']).encode())
    row = connect(db).execute('SELECT body,hash FROM output').fetchone()
    body = json.loads(row['body'])
    assert set(body) == {'id', 'amount', 'score', 'score_label', 'status'}
    assert body['score'] == 50.0 and row['hash'] == engine.sha(row['body'].encode())
    check = operations.verify_delivery(db, delivery['id'])
    assert check['items'][0]['status'] == '已核验'


def test_required_restricted_field_holds_both_routes(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(required=('id', 'score_label')), [envelope()])
    for consumer, route, reason in [('r1', 'reject_envelope', 'permission_restricted'),
                                    ('r2', 'redact_optional', 'required_field_restricted')]:
        operations.policy(db, consumer, h, 1000, route=route, **PUBLIC)
        allocation = operations.allocate(db, consumer)
        assert allocation['items'][0]['status'] == '待核'
        assert allocation['items'][0]['reason'] == reason
        assert operations.dispatch(db, consumer)['status'] == '暂缓'


def test_duplicate_entity_still_held_with_permissions(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope(value=1), envelope(value=2)])
    operations.policy(db, 'c', h, 1000, route='reject_envelope', **FULL)
    allocation = operations.allocate(db, 'c')
    assert [x['reason'] for x in allocation['items']] == ['duplicate_entity', 'duplicate_entity']
    assert operations.dispatch(db, 'c')['status'] == '暂缓'


def test_amount_quota_merges_with_permission_regime(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(),
                       [envelope(entity='A', value=2), envelope(entity='B', value=3)])
    operations.policy(db, 'tight', h, 400, route='redact_optional', **FULL)
    result = operations.allocate(db, 'tight')
    assert [x['status'] for x in result['items']] == ['已配额', '拒配']
    assert result['used'] == 200
    assert all(x['permission'] == 'deliver' for x in result['items'])
    operations.policy(db, 'deny', h, 400, route='reject_envelope', **PUBLIC)
    denied = operations.allocate(db, 'deny')
    assert denied['used'] == 0
    assert all(x['status'] == '待核' and x['reason'] == 'permission_restricted'
               for x in denied['items'])


def test_migration_block_not_bypassed_with_permissions(tmp_path):
    db, baseline = setup_case(tmp_path, perm_contract(),
                              [envelope(entity='A', value=2), envelope(entity='B', value=3)])
    target = perm_contract(target_version='v3')
    target['rules'][1]['factor'] = 110
    target_hash = engine.freeze(db, target)
    engine.translate(db, target_hash)
    migration.plan(db, 'cutover', baseline, target_hash, 10)
    assert migration.compare(db, 'cutover')['status'] == '阻断'
    operations.policy(db, 'new-consumer', target_hash, 10000, route='redact_optional', **FULL)
    assert [x['status'] for x in operations.allocate(db, 'new-consumer')['items']] == ['已配额', '已配额']
    assert operations.dispatch(db, 'new-consumer')['status'] == '暂缓'


def test_projection_receipt_cannot_be_forged(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'red', h, 1000, route='redact_optional', **PUBLIC)
    operations.policy(db, 'full', h, 1000, route='reject_envelope', **FULL)
    red = operations.dispatch(db, 'red')
    full = operations.dispatch(db, 'full')
    red_item, full_item = red['items'][0], full['items'][0]
    output_hash = connect(db).execute('SELECT hash FROM output').fetchone()[0]
    assert full_item['hash'] == output_hash
    assert red_item['hash'] != output_hash
    with pytest.raises(ValueError, match='delivery_item_mismatch'):
        operations.acknowledge(db, red['id'], red_item['output_id'], output_hash, '接收')
    with pytest.raises(ValueError, match='delivery_item_mismatch'):
        operations.acknowledge(db, red['id'], red_item['output_id'], full_item['hash'], '接收')
    with pytest.raises(ValueError, match='delivery_item_mismatch'):
        operations.acknowledge(db, full['id'], full_item['output_id'], red_item['hash'], '接收')
    result = operations.acknowledge(db, red['id'], red_item['output_id'],
                                    red_item['hash'], '接收')
    assert result['status'] == '已交付'


def test_delivery_projection_tampering_detected(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'red', h, 1000, route='redact_optional', **PUBLIC)
    delivery = operations.dispatch(db, 'red')
    item = delivery['items'][0]
    assert operations.verify_delivery(db, delivery['id'])['items'][0]['status'] == '已核验'
    with connect(db) as conn:
        conn.execute("UPDATE delivery_item SET projection='{}' WHERE delivery_id=?",
                     (delivery['id'],))
    issues = operations.verify_delivery(db, delivery['id'])['items'][0]['issues']
    assert 'projection_mismatch' in issues and 'projection_hash' in issues
    with connect(db) as conn:
        conn.execute('UPDATE delivery_item SET projection=? WHERE delivery_id=?',
                     (engine.canonical(item['projection']), delivery['id']))
        conn.execute("UPDATE delivery_item SET redacted='[\"score\"]' WHERE delivery_id=?",
                     (delivery['id'],))
    issues = operations.verify_delivery(db, delivery['id'])['items'][0]['issues']
    assert 'redaction_mismatch' in issues


def test_source_evidence_tampering_detected(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'red', h, 1000, route='redact_optional', **PUBLIC)
    delivery = operations.dispatch(db, 'red')
    with connect(db) as conn:
        conn.execute("UPDATE evidence SET pointer='/profile/other' WHERE field='score'")
    assert 'evidence_mismatch' in engine.verify(db, h)[0]['issues']
    assert 'evidence_mismatch' in operations.verify_delivery(db, delivery['id'])['items'][0]['issues']
    allocation = operations.allocate(db, 'red')
    assert allocation['items'][0]['reason'] == 'output_unverified'


def test_permission_version_change_new_decision_receipts_untouched(tmp_path):
    db, h1 = setup_case(tmp_path, perm_contract(version='p1'), [envelope()])
    operations.policy(db, 'early', h1, 1000, route='reject_envelope', **FULL)
    first = operations.dispatch(db, 'early')
    operations.acknowledge(db, first['id'], first['items'][0]['output_id'],
                           first['items'][0]['hash'], '接收')
    assert operations.delivery_status(db, first['id'])['status'] == '已交付'

    tightened = dict(perm_contract()['source_permissions'])
    tightened['/legacy/value'] = {'label': 'restricted', 'purpose': 'billing'}
    contract2 = perm_contract(version='p2', labels=tightened, target_version='v3')
    h2 = engine.freeze(db, contract2)
    engine.translate(db, h2)
    operations.policy(db, 'late', h2, 1000, route='reject_envelope', **PUBLIC)
    second = operations.dispatch(db, 'late')
    assert second['status'] == '暂缓' and second['permission_version'] == 'p2'

    old = operations.delivery_status(db, first['id'])
    assert old['status'] == '已交付' and old['permission_version'] == 'p1'
    acks = connect(db).execute('SELECT hash,result FROM delivery_ack WHERE delivery_id=?',
                               (first['id'],)).fetchall()
    assert [(a['hash'], a['result']) for a in acks] == [(first['items'][0]['hash'], '接收')]
    again = operations.dispatch(db, 'early')
    assert again['id'] == first['id'] and again['items'] == old['items']


def test_deterministic_replay(tmp_path):
    envelopes = [envelope(entity='A', value=1), envelope(entity='B', value=2)]
    db, h = setup_case(tmp_path, perm_contract(), envelopes)
    operations.policy(db, 'c', h, 1000, route='redact_optional', **PUBLIC)
    assert operations.allocate(db, 'c') == operations.allocate(db, 'c')
    first = operations.dispatch(db, 'c')
    assert operations.dispatch(db, 'c') == first
    assert engine.translate(db, h) == engine.translate(db, h)
    assert connect(db).execute('SELECT count(*) FROM output').fetchone()[0] == 2

    db2, h2 = setup_case(tmp_path, perm_contract(), envelopes, name='db2')
    assert h2 == h
    operations.policy(db2, 'c', h2, 1000, route='redact_optional', **PUBLIC)
    replayed = operations.dispatch(db2, 'c')
    assert [i['hash'] for i in replayed['items']] == [i['hash'] for i in first['items']]
    assert [i['redacted'] for i in replayed['items']] == [i['redacted'] for i in first['items']]


def test_policy_immutable_includes_permission_terms(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'c', h, 100, route='reject_envelope', **PUBLIC)
    with pytest.raises(ValueError, match='policy_is_immutable'):
        operations.policy(db, 'c', h, 100, route='redact_optional', **PUBLIC)
    with pytest.raises(ValueError, match='policy_is_immutable'):
        operations.policy(db, 'c', h, 100, allowed_labels=['public', 'restricted'],
                          allowed_purposes=PUBLIC['allowed_purposes'], route='reject_envelope')
    with pytest.raises(ValueError, match='invalid_consumer_policy'):
        operations.policy(db, 'c2', h, 100, route='bogus')
    same = operations.policy(db, 'c', h, 100, route='reject_envelope', **PUBLIC)
    assert same['route'] == 'reject_envelope' and same['allowed_labels'] == ['public']


def test_report_lists_decisions_without_leaking_values(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    operations.policy(db, 'red', h, 1000, route='redact_optional', **PUBLIC)
    operations.dispatch(db, 'red')
    operations.policy(db, 'rej', h, 1000, route='reject_envelope', **PUBLIC)
    operations.dispatch(db, 'rej')
    report_path = engine.report(db, h, tmp_path / 'report.json')
    text = report_path.read_text(encoding='utf-8')
    report = json.loads(text)
    assert report['permission_regime']['version'] == 'p1'
    assert 'body' not in report['outputs'][0]
    assert report['outputs'][0]['field_permissions']['score'] == [['restricted', 'risk_scoring']]
    deliveries = {d['consumer']: d for d in report['deliveries']}
    assert deliveries['red']['items'][0]['redacted'] == ['score', 'score_label']
    assert deliveries['red']['allocations'][0]['reason'] == 'within_limit'
    assert deliveries['red']['allocations'][0]['permission'] == 'redact'
    assert deliveries['rej']['status'] == '暂缓'
    assert deliveries['rej']['items'] == []
    assert deliveries['rej']['allocations'][0]['reason'] == 'permission_restricted'
    assert '/profile/private_score' in text
    assert '50.0' not in text and '0.5' not in text


def run_cli(*args):
    return subprocess.run([sys.executable, '-m', 'contractbridge', *args],
                          cwd=ROOT, capture_output=True, text=True, check=True)


def test_cli_policy_dispatch_and_verify_delivery(tmp_path):
    db, h = setup_case(tmp_path, perm_contract(), [envelope()])
    out = run_cli('consumer-policy', '--db', str(db), '--consumer', 'cli',
                  '--contract-hash', h, '--limit', '1000', '--labels', 'public',
                  '--purposes', 'identification,billing,status', '--route', 'redact_optional')
    assert 'redact_optional' in out.stdout
    delivery = ast.literal_eval(run_cli('dispatch', '--db', str(db), '--consumer', 'cli').stdout)
    assert delivery['status'] == '待回执'
    assert delivery['items'][0]['redacted'] == ['score', 'score_label']
    out = run_cli('verify-delivery', '--db', str(db), '--delivery-id', str(delivery['id']))
    assert '已核验' in out.stdout
