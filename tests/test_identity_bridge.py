import json
import pytest
from contractbridge import engine, migration
from contractbridge.store import connect

T0 = '2026-01-01T00:00:00Z'
T = '2026-06-01T00:00:00Z'


def cfg(**extra):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id', 'amount'],
                'identity_parts': ['/legacy/site', '/legacy/local_id'],
                'rules': [{'target': 'id', 'source': '/entity_id'},
                          {'target': 'amount', 'source': '/value', 'op': 'scale', 'factor': 100}],
                'errors': {}}
    contract.update(extra)
    return contract


def decl(declaration_id, key, stable, subject, start, end=None, version='1', source='registry#1'):
    return {'declaration_id': declaration_id, 'legacy_key': key, 'stable_id': stable,
            'subject': subject, 'valid_from': start, 'valid_to': end,
            'source_digest': source, 'version': version}


def declare_reused_key(db):
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    engine.declare_bridge(db, decl('D-2', 'S|7', 'N2', 'Bob', T, None))


def legacy_env(subject, value, site='S', local='7', event_time=None, state=None):
    obj = {'version': 'v1', 'subject': subject, 'value': value,
           'legacy': {'site': site, 'local_id': local}}
    if event_time:
        obj['event_time'] = event_time
    if state:
        obj['state'] = state
    return obj


def new_env(stable, subject, value, event_time=None, state=None):
    obj = {'version': 'v2', 'entity_id': stable, 'subject': subject, 'value': value, 'new': {}}
    if event_time:
        obj['event_time'] = event_time
    if state:
        obj['state'] = state
    return obj


def write_source(tmp_path, name, rows):
    path = tmp_path / f'{name}.jsonl'
    path.write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
    return path


def issue_codes(db, code):
    return connect(db).execute('SELECT count(*) FROM issue WHERE code=?', (code,)).fetchone()[0]


def attributions(db):
    return [dict(x) for x in connect(db).execute('SELECT * FROM attribution ORDER BY run_id,envelope_id')]


def test_reused_key_temporal_attribution_separates_subjects(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    declare_reused_key(db)
    rows = [legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z', state='new'),
            legacy_env('Alice', 2, event_time='2026-04-01T00:00:00Z', state='active'),
            legacy_env('Bob', 3, event_time='2026-07-01T00:00:00Z', state='new'),
            legacy_env('Bob', 3, event_time='2026-08-01T00:00:00Z', state='closed'),
            new_env('N1', 'Alice', 2, event_time='2026-05-01T00:00:00Z', state='active'),
            new_env('N2', 'Bob', 3, event_time='2026-09-01T00:00:00Z', state='closed')]
    engine.ingest(db, write_source(tmp_path, 'x', rows), cfg())
    engine.translate(db, h)
    conn = connect(db)
    entities = dict(conn.execute('SELECT id,subject FROM entity').fetchall())
    assert entities == {'N1': 'Alice', 'N2': 'Bob'}
    for code in ('identity_conflict', 'cross_package_identity', 'state_transition',
                     'state_regression', 'cross_package_state'):
        assert issue_codes(db, code) == 0
    bridged = [a for a in attributions(db) if a['legacy_key'] == 'S|7']
    assert [a['stable_id'] for a in bridged] == ['N1', 'N1', 'N2', 'N2']
    assert {a['declaration_id'] for a in bridged} == {'D-1', 'D-2'}
    bodies = [json.loads(x[0]) for x in conn.execute('SELECT body FROM output ORDER BY id')]
    assert [b['id'] for b in bodies] == ['N1', 'N1', 'N2', 'N2', 'N1', 'N2']
    assert conn.execute("SELECT status FROM run").fetchall()[0][0] == '已核验'


def test_boundary_instants_are_half_open(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    declare_reused_key(db)
    rows = [legacy_env('Alice', 1, event_time='2026-01-01T00:00:00Z'),
            legacy_env('Alice', 1, event_time='2026-05-31T23:59:59Z'),
            legacy_env('Bob', 1, event_time='2026-06-01T00:00:00Z')]
    engine.ingest(db, write_source(tmp_path, 'x', rows), cfg())
    engine.translate(db, h)
    assert [a['stable_id'] for a in attributions(db)] == ['N1', 'N1', 'N2']
    assert all(a['status'] == 'attributed' for a in attributions(db))


def test_overlapping_declarations_held_regardless_of_import_order(tmp_path):
    def build(order):
        db = tmp_path / ('db_a' if order == 0 else 'db_b')
        h = engine.freeze(db, cfg())
        pair = [decl('D-1', 'S|7', 'N1', 'Alice', T0, T),
                decl('D-2', 'S|7', 'N2', 'Bob', '2026-03-01T00:00:00Z', '2026-09-01T00:00:00Z')]
        for d in (pair if order == 0 else pair[::-1]):
            engine.declare_bridge(db, d)
        rows = [legacy_env('Alice', 1, event_time='2026-02-01T00:00:00Z'),
                legacy_env('Alice', 1, event_time='2026-04-01T00:00:00Z'),
                legacy_env('Bob', 1, event_time='2026-07-01T00:00:00Z')]
        engine.ingest(db, write_source(tmp_path, f'x{order}', rows), cfg())
        engine.translate(db, h)
        return db
    results = []
    for order in (0, 1):
        db = build(order)
        by_instant = {a['instant']: a for a in attributions(db)}
        assert by_instant['2026-02-01T00:00:00+00:00']['stable_id'] == 'N1'
        assert by_instant['2026-07-01T00:00:00+00:00']['stable_id'] == 'N2'
        held = by_instant['2026-04-01T00:00:00+00:00']
        assert held['status'] == 'held' and held['stable_id'] is None
        assert held['reason'] == 'bridge_interval_overlap'
        results.append((held['status'], held['reason']))
        assert issue_codes(db, 'identity_attribution_held') == 1
        conn = connect(db)
        held_envelope = conn.execute('SELECT envelope_id FROM attribution WHERE status=?', ('held',)).fetchone()[0]
        assert conn.execute('SELECT status FROM output WHERE envelope_id=?', (held_envelope,)).fetchone()[0] == '待核'
    assert results[0] == results[1]


def test_missing_event_time_strict_vs_batch_anchor_contracts(tmp_path):
    db = tmp_path / 'db'
    strict = cfg()
    batch = cfg(missing_event_time='batch_anchor')
    batch['versions'][-1]['version'] = 'v2b'
    strict_hash = engine.freeze(db, strict)
    batch_hash = engine.freeze(db, batch)
    assert strict_hash != batch_hash
    declare_reused_key(db)
    engine.ingest(db, write_source(tmp_path, 'anchored', [legacy_env('Bob', 3, state='closed')]),
                  strict, collected_at='2026-07-01T00:00:00Z')
    engine.ingest(db, write_source(tmp_path, 'stable', [new_env('N2', 'Bob', 3, event_time='2026-08-01T00:00:00Z', state='active')]), strict)
    engine.translate(db, strict_hash)
    assert issue_codes(db, 'identity_attribution_held') == 1
    assert issue_codes(db, 'state_transition') == 0
    held = [a for a in attributions(db) if a['legacy_key'] == 'S|7']
    assert held[0]['status'] == 'held' and held[0]['reason'] == 'missing_event_time'
    engine.translate(db, batch_hash)
    anchored = [a for a in attributions(db)
                if a['legacy_key'] == 'S|7' and a['status'] == 'attributed']
    assert len(anchored) == 1
    assert anchored[0]['stable_id'] == 'N2'
    assert anchored[0]['instant'] == '2026-07-01T00:00:00+00:00'
    assert anchored[0]['instant_source'] == 'batch_anchor'
    assert anchored[0]['declaration_source'] == 'registry#1'
    assert all(a['stable_id'] != 'N1' for a in attributions(db) if a['legacy_key'] == 'S|7')
    assert issue_codes(db, 'state_transition') == 1
    assert connect(db).execute('SELECT count(*) FROM entity WHERE id=?', ('N1',)).fetchone()[0] == 0


def test_batch_anchor_requires_verifiable_source(tmp_path):
    db = tmp_path / 'db'
    batch = cfg(missing_event_time='batch_anchor')
    batch_hash = engine.freeze(db, batch)
    declare_reused_key(db)
    engine.ingest(db, write_source(tmp_path, 'no_anchor', [legacy_env('Bob', 3, state='new')]), batch)
    tampered = write_source(tmp_path, 'tampered', [legacy_env('Bob', 4, state='new')])
    engine.ingest(db, tampered, batch, collected_at='2026-07-01T00:00:00Z')
    conn = connect(db)
    with conn:
        conn.execute('UPDATE source SET body=? WHERE collected_at IS NOT NULL', (b'forged',))
    engine.translate(db, batch_hash)
    held = [a for a in attributions(db) if a['status'] == 'held']
    assert len(held) == 2
    assert {a['reason'] for a in held} == {'batch_anchor_unverifiable'}
    assert issue_codes(db, 'identity_attribution_held') == 2


def test_out_of_order_backfill_attributes_by_event_time(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    declare_reused_key(db)
    engine.ingest(db, write_source(tmp_path, 'first', [
        legacy_env('Bob', 3, event_time='2026-07-01T00:00:00Z', state='new'),
        new_env('N2', 'Bob', 3, event_time='2026-08-01T00:00:00Z', state='active')]), cfg())
    engine.translate(db, h)
    engine.ingest(db, write_source(tmp_path, 'backfill', [
        legacy_env('Alice', 2, event_time='2026-02-01T00:00:00Z', state='new'),
        legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z', state='active')]), cfg())
    engine.translate(db, h)
    for code in ('state_transition', 'state_regression', 'cross_package_state', 'identity_conflict'):
        assert issue_codes(db, code) == 0
    backfilled = [a for a in attributions(db) if a['instant'] in (
        '2026-02-01T00:00:00+00:00', '2026-03-01T00:00:00+00:00')]
    assert {a['stable_id'] for a in backfilled} == {'N1'}
    conn = connect(db)
    assert conn.execute('SELECT count(*) FROM run').fetchone()[0] == 2
    entities = dict(conn.execute('SELECT id,subject FROM entity').fetchall())
    assert entities == {'N2': 'Bob', 'N1': 'Alice'}


def test_attribution_drives_identity_conflict(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    engine.ingest(db, write_source(tmp_path, 'x', [
        legacy_env('Carol', 2, event_time='2026-03-01T00:00:00Z'),
        new_env('N1', 'Alice', 2, event_time='2026-04-01T00:00:00Z')]), cfg())
    engine.translate(db, h)
    assert issue_codes(db, 'identity_conflict') == 1
    assert connect(db).execute('SELECT subject FROM entity WHERE id=?', ('N1',)).fetchone()[0] == 'Carol'


def test_attribution_drives_cross_key_state_transition(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    engine.ingest(db, write_source(tmp_path, 'legacy', [
        legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z', state='closed')]), cfg())
    engine.ingest(db, write_source(tmp_path, 'stable', [
        new_env('N1', 'Alice', 2, event_time='2026-04-01T00:00:00Z', state='active')]), cfg())
    engine.translate(db, h)
    assert issue_codes(db, 'state_transition') == 1
    flagged = connect(db).execute("SELECT detail FROM issue WHERE code='state_transition'").fetchone()[0]
    assert flagged == 'N1'


def test_key_outside_declared_intervals_stays_unbridged(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    engine.ingest(db, write_source(tmp_path, 'x', [
        legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z'),
        legacy_env('Bob', 3, event_time='2026-09-01T00:00:00Z')]), cfg())
    engine.translate(db, h)
    by_stable = {a['stable_id']: a['status'] for a in attributions(db)}
    assert by_stable == {'N1': 'attributed', None: 'unbridged'}
    entities = dict(connect(db).execute('SELECT id,subject FROM entity').fetchall())
    assert entities == {'N1': 'Alice', 'S|7': 'Bob'}
    assert issue_codes(db, 'identity_conflict') == 0


def test_declaration_immutability_replay_and_validation(tmp_path):
    db = tmp_path / 'db'
    first = engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    replay = engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    assert first == replay
    assert connect(db).execute('SELECT count(*) FROM bridge_declaration').fetchone()[0] == 1
    with pytest.raises(ValueError, match='bridge_declaration_conflict'):
        engine.declare_bridge(db, decl('D-1', 'S|7', 'N2', 'Alice', T0, T))
    with pytest.raises(ValueError, match='invalid_bridge_declaration'):
        engine.declare_bridge(db, decl('D-2', 'S|7', 'N2', 'Bob', T, T0))
    with pytest.raises(ValueError, match='invalid_bridge_declaration'):
        engine.declare_bridge(db, decl('D-3', 'S|7', 'N2', 'Bob', 'not-a-date'))
    with pytest.raises(ValueError, match='invalid_bridge_declaration'):
        engine.declare_bridge(db, decl('D-4', 'S|7', 'N2', '', T0))
    with pytest.raises(ValueError, match='invalid_missing_event_time_policy'):
        engine.freeze(tmp_path / 'db2', cfg(missing_event_time='sometimes'))
    with pytest.raises(ValueError, match='invalid_collected_at'):
        engine.ingest(tmp_path / 'db3', write_source(tmp_path, 'y', [legacy_env('A', 1)]), cfg(),
                      collected_at='yesterday')


def test_declaration_update_spawns_new_run_without_rewriting_history(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    engine.ingest(db, write_source(tmp_path, 'x', [legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z')]), cfg())
    first_outputs = engine.translate(db, h)
    conn = connect(db)
    empty_version = conn.execute('SELECT bridge_version FROM run').fetchone()[0]
    assert json.loads(conn.execute('SELECT body FROM output').fetchone()[0])['id'] == 'S|7'
    declared = engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    assert declared['bridge_version'] != empty_version
    second_outputs = engine.translate(db, h)
    assert first_outputs != second_outputs
    runs = conn.execute('SELECT bridge_version FROM run ORDER BY id').fetchall()
    assert [r[0] for r in runs] == [empty_version, declared['bridge_version']]
    bodies = [json.loads(x[0])['id'] for x in conn.execute('SELECT body FROM output ORDER BY id')]
    assert bodies == ['S|7', 'N1']
    assert [x['status'] for x in engine.verify(db, h)] == ['已核验', '已核验']
    report = json.loads(engine.report(db, h, tmp_path / 'r.json').read_text(encoding='utf-8'))
    assert len(report['attributions']) == 2
    by_version = {a['bridge_version']: a for a in report['attributions']}
    assert by_version[empty_version]['status'] == 'unbridged'
    bridged = by_version[declared['bridge_version']]
    assert bridged['stable_id'] == 'N1' and bridged['declaration_source'] == 'registry#1'
    assert bridged['legacy_key'] == 'S|7' and bridged['instant'] == '2026-03-01T00:00:00+00:00'


def test_migration_compare_uses_one_frozen_bridge_version(tmp_path):
    db = tmp_path / 'db'
    baseline = engine.freeze(db, cfg())
    engine.ingest(db, write_source(tmp_path, 'x', [legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z')]), cfg())
    engine.translate(db, baseline)
    declared = engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    target_contract = cfg()
    target_contract['versions'][-1]['version'] = 'v3'
    target = engine.freeze(db, target_contract)
    engine.translate(db, target)
    migration.plan(db, 'cutover', baseline, target, 10)
    compared = migration.compare(db, 'cutover')
    assert compared['status'] == '可切换'
    assert compared['diffs'][0]['status'] == '兼容'
    assert compared['bridge_version'] == declared['bridge_version']
    conn = connect(db)
    rows = [tuple(x) for x in conn.execute('SELECT bridge_version,status FROM migration_diff').fetchall()]
    assert rows == [(declared['bridge_version'], '兼容')]
    engine.declare_bridge(db, decl('D-9', 'OTHER', 'N9', 'Mallory', T0, None))
    recompared = migration.compare(db, 'cutover')
    assert recompared['bridge_version'] != declared['bridge_version']
    assert recompared['status'] == '可切换'
    versions = {x[0] for x in conn.execute('SELECT bridge_version FROM migration_diff').fetchall()}
    assert versions == {declared['bridge_version'], recompared['bridge_version']}
    history = conn.execute('SELECT bridge_version,status FROM migration_compare ORDER BY created,bridge_version').fetchall()
    assert {x[0] for x in history} == versions
    assert all(x[1] == '可切换' for x in history)


def test_migration_compare_blocks_cross_subject_drift(tmp_path):
    db = tmp_path / 'db'
    baseline = engine.freeze(db, cfg())
    target_contract = cfg()
    target_contract['versions'][-1]['version'] = 'v3'
    target_contract['rules'][0] = {'target': 'id', 'source': '/legacy/alt_id'}
    target = engine.freeze(db, target_contract)
    row = legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z')
    row['legacy']['alt_id'] = 'STRANGER'
    engine.ingest(db, write_source(tmp_path, 'x', [row]), cfg())
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T))
    engine.translate(db, baseline)
    engine.translate(db, target)
    migration.plan(db, 'cutover', baseline, target, 10)
    compared = migration.compare(db, 'cutover')
    assert compared['status'] == '阻断'
    assert compared['diffs'][0]['reason'] == 'subject_drift'


def test_report_lists_per_envelope_attribution(tmp_path):
    db = tmp_path / 'db'
    h = engine.freeze(db, cfg())
    engine.declare_bridge(db, decl('D-1', 'S|7', 'N1', 'Alice', T0, T, source='registry#7'))
    rows = [legacy_env('Alice', 2, event_time='2026-03-01T00:00:00Z'),
            legacy_env('Alice', 2)]
    engine.ingest(db, write_source(tmp_path, 'x', rows), cfg())
    engine.translate(db, h)
    report = json.loads(engine.report(db, h, tmp_path / 'r.json').read_text(encoding='utf-8'))
    assert len(report['attributions']) == 2
    attributed = [a for a in report['attributions'] if a['status'] == 'attributed'][0]
    assert attributed['legacy_key'] == 'S|7'
    assert attributed['instant'] == '2026-03-01T00:00:00+00:00'
    assert attributed['declaration_source'] == 'registry#7'
    assert attributed['stable_id'] == 'N1'
    held = [a for a in report['attributions'] if a['status'] == 'held'][0]
    assert held['reason'] == 'missing_event_time' and held['stable_id'] is None
    assert report['bridge_declarations'][0]['declaration_id'] == 'D-1'
    assert report['bridge_version']
