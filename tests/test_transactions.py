"""Cross-interface transaction reconciliation tests.

Every fixture is local synthetic JSONL; no network or real API is involved.
The per-envelope engine behavior is covered in test_bridge.py and is never
rewritten by the transaction layer — these tests assert the independent,
traceable transaction verdict and its causal effect on cohort comparison.
"""
import json
import pytest
from contractbridge import engine, migration, transactions
from contractbridge.store import connect


def tx_contract(protocol, required_events=None):
    rules = [
        {'target': 'id', 'source': '/entity_id'},
        {'target': 'txn_id', 'source': '/txn'},
        {'target': 'event', 'source': '/kind', 'op': 'enum',
         'values': {'order': 'order', 'auth': 'authorize', 'capture': 'capture',
                    'refund': 'refund', 'void': 'void'}},
        {'target': 'event_time', 'source': '/biz_time'},
        {'target': 'amount', 'source': '/amount'},
        {'target': 'event_key', 'source': '/event_key'},
        {'target': 'credential', 'source': '/credential', 'nullable': True},
    ]
    tx = {'protocol': protocol, 'transaction_id_field': 'txn_id',
          'event_field': 'event', 'time_field': 'event_time',
          'amount_field': 'amount', 'event_id_field': 'event_key',
          'credential_field': 'credential',
          'required_events': required_events or ['order', 'capture']}
    return {'versions': [{'version': 't1', 'signature': ['/biz_time']},
                         {'version': 't2', 'signature': ['/new_event']}],
            'required': ['id', 'txn_id', 'event', 'event_time', 'amount', 'event_key'],
            'rules': rules, 'errors': {}, 'transaction': tx}


def env(entity, kind, amount, key, time, credential=None, txn='T-100', version='t1', extra=None):
    obj = {'version': version, 'entity_id': entity, 'subject': 'Payment platform',
           'txn': txn, 'kind': kind, 'biz_time': time, 'amount': amount,
           'event_key': key, 'status': 'ok', 'baseline_marker': 'db-cohort'}
    if credential:
        obj['credential'] = credential
    if extra:
        obj.update(extra)
    return json.dumps(obj, ensure_ascii=False)


def build(tmp_path, protocol, lines, required_events=None):
    db = tmp_path / 'ledger'
    contract = tx_contract(protocol, required_events)
    h = engine.freeze(db, contract)
    src = tmp_path / 'input.jsonl'
    src.write_text('\n'.join(lines), encoding='utf-8')
    engine.ingest(db, src, contract)
    engine.translate(db, h)
    return db, contract, h


def order_capture(credential='cred-1', amount=100, txn='T-100'):
    return [env(f'ORD-{txn}', 'order', amount, f'{txn}-order', '2026-01-01T10:00:00Z', txn=txn),
            env(f'PAY-{txn}', 'capture', amount, f'{txn}-cap', '2026-01-01T10:05:00Z',
                credential, txn=txn)]


def verdict_by_id(results):
    return {r['transaction_id']: r for r in results}


def gap_codes(result):
    return {g['code'] for g in result['gaps']}


# --- protocol semantics -----------------------------------------------------

def test_preauth_requires_authorization_before_capture(tmp_path):
    db, _, h = build(tmp_path, 'preauth', order_capture())
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert {'authorization_missing', 'capture_exceeds_authorization'} <= gap_codes(result)


def test_preauth_verified_when_authorization_covers_capture(tmp_path):
    lines = [env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z'),
             env('AUTH-1', 'auth', 100, 'k-auth', '2026-01-01T10:01:00Z'),
             env('PAY-1', 'capture', 100, 'k-cap', '2026-01-01T10:02:00Z', 'cred-1')]
    db, _, h = build(tmp_path, 'preauth', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED
    assert result['balances'] == {'order': 100.0, 'authorized': 100.0, 'captured': 100.0,
                                  'refunded': 0.0, 'voided': 0.0, 'refundable': 100.0}


def test_direct_debit_verified_without_authorization_event(tmp_path):
    # Same order 100 / capture 100 inputs, no authorization event: this is the
    # protocol-frozen fork that distinguishes the two real business agreements.
    db, _, h = build(tmp_path, 'direct_debit', order_capture())
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED
    assert result['balances']['authorized'] == 0.0
    assert result['balances']['captured'] == 100.0


def test_protocol_is_frozen_and_never_auto_switches(tmp_path):
    db, contract, h = build(tmp_path, 'preauth', order_capture())
    # The pending verdict must stay pending even after the evidence gap exists;
    # re-running reconciliation cannot silently move the transaction to direct debit.
    first = transactions.reconcile_transactions(db, h)
    second = transactions.reconcile_transactions(db, h)
    assert first == second
    stored = json.loads(connect(db).execute(
        'SELECT body FROM contract WHERE hash=?', (h,)).fetchone()['body'])
    assert stored['transaction']['protocol'] == 'preauth'


def test_direct_debit_requires_non_reusable_credential(tmp_path):
    lines = [env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z'),
             env('PAY-1', 'capture', 100, 'k-cap', '2026-01-01T10:05:00Z')]
    db, _, h = build(tmp_path, 'direct_debit', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'direct_debit_credential_missing' in gap_codes(result)


def test_credential_reused_by_another_transaction_blocks_both_protocols(tmp_path):
    for protocol in ('preauth', 'direct_debit'):
        lines = order_capture('shared-cred', txn='T-100') + order_capture('shared-cred', txn='T-200')
        db, _, h = build(tmp_path / protocol, protocol, lines)
        results = verdict_by_id(transactions.reconcile_transactions(db, h))
        for txn in ('T-100', 'T-200'):
            assert results[txn]['status'] == transactions.PENDING
            assert 'credential_reused' in gap_codes(results[txn])


# --- amount conservation ----------------------------------------------------

def test_capture_cannot_exceed_authorization(tmp_path):
    lines = [env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z'),
             env('AUTH-1', 'auth', 60, 'k-auth', '2026-01-01T10:01:00Z'),
             env('PAY-1', 'capture', 100, 'k-cap', '2026-01-01T10:02:00Z', 'cred-1')]
    db, _, h = build(tmp_path, 'preauth', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'capture_exceeds_authorization' in gap_codes(result)


def test_refund_cannot_exceed_captured_amount(tmp_path):
    lines = order_capture('cred-1') + [
        env('REF-1', 'refund', 140, 'k-refund', '2026-01-02T08:00:00Z')]
    db, _, h = build(tmp_path, 'direct_debit', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'refund_exceeds_captured' in gap_codes(result)


def test_late_refund_reduces_refundable_balance_and_keeps_history(tmp_path):
    first_lines = order_capture('cred-1')
    db, contract, h = build(tmp_path, 'direct_debit', first_lines)
    before = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert before['balances']['refundable'] == 100.0
    late = tmp_path / 'late.jsonl'
    late.write_text(env('REF-1', 'refund', 30, 'k-refund', '2026-01-03T08:00:00Z'))
    engine.ingest(db, late, contract)
    engine.translate(db, h)
    after = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert after['balances']['captured'] == 100.0
    assert after['balances']['refunded'] == 30.0
    assert after['balances']['refundable'] == 70.0
    # Historical order/capture events remain on the chain in business order.
    stored = [dict(r) for r in connect(db).execute(
        'SELECT event,amount,ordinal FROM transaction_event ORDER BY ordinal')]
    assert [e['event'] for e in stored] == ['order', 'capture', 'refund']


def test_exact_replay_is_idempotent_and_not_double_counted(tmp_path):
    lines = order_capture('cred-1')
    # The same business event key is re-delivered with an identical payload.
    lines.append(env('PAY-1', 'capture', 100, 'T-100-cap', '2026-01-01T10:05:00Z', 'cred-1'))
    db, _, h = build(tmp_path, 'direct_debit', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED
    assert result['balances']['captured'] == 100.0
    row = connect(db).execute(
        "SELECT replay_count FROM transaction_event WHERE event='capture'").fetchone()
    assert row['replay_count'] == 2
    # Re-running reconciliation stays idempotent at the storage layer.
    transactions.reconcile_transactions(db, h)
    assert connect(db).execute('SELECT count(*) FROM transaction_event').fetchone()[0] == 2


def test_conflicting_replay_breaks_convergence(tmp_path):
    lines = order_capture('cred-1')
    # Same event key, different amount: the replay cannot be silently merged.
    lines.append(env('PAY-1', 'capture', 120, 'T-100-cap', '2026-01-01T10:06:00Z', 'cred-1'))
    db, _, h = build(tmp_path, 'direct_debit', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'replay_conflict' in gap_codes(result)


# --- ordering, missing interfaces, ambiguity --------------------------------

def test_out_of_order_envelopes_reconstruct_by_business_time(tmp_path):
    # Wall-clock ingestion is refund-first; business instants still order the chain.
    lines = [env('REF-1', 'refund', 30, 'k-refund', '2026-01-03T08:00:00Z'),
             env('PAY-1', 'capture', 100, 'k-cap', '2026-01-01T10:05:00Z', 'cred-1'),
             env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z')]
    db, _, h = build(tmp_path, 'direct_debit', lines)
    stored = [r['event'] for r in connect(db).execute(
        'SELECT event FROM transaction_event ORDER BY ordinal')]
    assert stored == ['order', 'capture', 'refund']
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED
    assert result['balances']['refundable'] == 70.0


def test_missing_required_interface_is_pending_with_named_gap(tmp_path):
    db, _, h = build(tmp_path, 'direct_debit',
                     [env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z')])
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'required_interface_missing' in gap_codes(result)


def test_missing_transaction_id_becomes_unattached_gap(tmp_path):
    # Contract whose transaction-id pointer defaults to an empty string when the
    # raw envelope omits it: the output itself verifies (no required fields are
    # broken), but the event cannot be attached to any transaction.
    contract = tx_contract('direct_debit')
    contract['rules'] = [r if r['target'] != 'txn_id' else
                         {'target': 'txn_id', 'source': '/txn', 'default': ''}
                         for r in contract['rules']]
    contract['required'].remove('txn_id')
    db = tmp_path / 'ledger'
    h = engine.freeze(db, contract)
    raw = json.loads(env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z'))
    del raw['txn']
    src = tmp_path / 'input.jsonl'
    src.write_text(json.dumps(raw, ensure_ascii=False), encoding='utf-8')
    engine.ingest(db, src, contract)
    engine.translate(db, h)
    assert engine.verify(db, h)[0]['status'] == '已核验'
    assert transactions.reconcile_transactions(db, h) == []
    gap = connect(db).execute(
        "SELECT code FROM transaction_gap WHERE transaction_pk IS NULL").fetchone()
    assert gap['code'] == 'transaction_id_missing'


def test_conflicting_transaction_id_pointers_are_ambiguous(tmp_path):
    contract = tx_contract('direct_debit')
    contract['rules'].append({'target': 'txn_id_alt', 'source': '/txn_alt'})
    contract['transaction']['transaction_id_fields'] = ['txn_id', 'txn_id_alt']
    db = tmp_path / 'ledger'
    h = engine.freeze(db, contract)
    src = tmp_path / 'input.jsonl'
    rows = [json.loads(x) for x in order_capture('cred-1')]
    for row in rows:
        row['txn_alt'] = 'T-999'
    src.write_text('\n'.join(json.dumps(r, ensure_ascii=False) for r in rows), encoding='utf-8')
    engine.ingest(db, src, contract)
    engine.translate(db, h)
    assert transactions.reconcile_transactions(db, h) == []
    gap = connect(db).execute(
        "SELECT code FROM transaction_gap WHERE transaction_pk IS NULL").fetchone()
    assert gap['code'] == 'transaction_id_ambiguous'


def test_unverified_output_never_feeds_a_success_transaction(tmp_path):
    db, contract, h = build(tmp_path, 'direct_debit', order_capture())
    # Tamper one translated output; verify must reject it and the transaction
    # layer must treat it as unattached rather than merge surface-legal JSON.
    with connect(db) as conn:
        conn.execute("UPDATE output SET body='{}' WHERE id=(SELECT min(id) FROM output)")
    results = transactions.reconcile_transactions(db, h)
    assert all(r['status'] == transactions.PENDING for r in results)
    assert connect(db).execute(
        "SELECT 1 FROM transaction_gap WHERE code='output_unverified'").fetchone()


def test_same_instant_same_event_with_different_amount_cannot_converge(tmp_path):
    instant = '2026-01-01T10:00:00Z'
    lines = [env('ORD-1', 'order', 100, 'k-order', instant),
             env('PAY-1a', 'capture', 100, 'k-cap', instant, 'cred-1'),
             env('PAY-1b', 'capture', 90, 'k-cap', instant, 'cred-1')]
    db, _, h = build(tmp_path, 'direct_debit', lines)
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.PENDING
    assert 'replay_conflict' in gap_codes(result)


def test_same_instant_events_follow_lifecycle_order(tmp_path):
    # Authorization and capture share one business instant: lifecycle ordering
    # must still apply authorization before capture, so conservation converges.
    instant = '2026-01-01T10:00:00Z'
    lines = [env('PAY-1', 'capture', 100, 'k-cap', instant, 'cred-1'),
             env('AUTH-1', 'auth', 100, 'k-auth', instant),
             env('ORD-1', 'order', 100, 'k-order', instant)]
    db, _, h = build(tmp_path, 'preauth', lines, required_events=['order', 'authorize'])
    stored = [r['event'] for r in connect(db).execute(
        'SELECT event FROM transaction_event ORDER BY ordinal')]
    assert stored == ['order', 'authorize', 'capture']
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED


def test_void_event_is_recorded_on_the_chain(tmp_path):
    lines = [env('ORD-1', 'order', 100, 'k-order', '2026-01-01T10:00:00Z'),
             env('AUTH-1', 'auth', 100, 'k-auth', '2026-01-01T10:01:00Z'),
             env('VOID-1', 'void', 100, 'k-void', '2026-01-01T10:02:00Z')]
    db, _, h = build(tmp_path, 'preauth', lines, required_events=['order', 'authorize'])
    result = verdict_by_id(transactions.reconcile_transactions(db, h))['T-100']
    assert result['status'] == transactions.VERIFIED
    assert result['balances']['voided'] == 100.0


# --- frozen contract validation ---------------------------------------------

def test_transaction_contract_validation_at_freeze(tmp_path):
    bad = tx_contract('direct_debit')
    bad['transaction']['protocol'] = 'switch-on-gap'
    with pytest.raises(ValueError, match='transaction_protocol_invalid'):
        engine.freeze(tmp_path / 'db1', bad)
    missing = tx_contract('direct_debit')
    del missing['transaction']['credential_field']
    with pytest.raises(ValueError, match='transaction_credential_field_required'):
        engine.freeze(tmp_path / 'db2', missing)
    unmapped = tx_contract('direct_debit')
    unmapped['transaction']['amount_field'] = 'ghost'
    with pytest.raises(ValueError, match='transaction_field_unmapped'):
        engine.freeze(tmp_path / 'db3', unmapped)


def test_contract_without_transaction_section_is_unchanged(tmp_path):
    contract = {'versions': [{'version': 'v1', 'signature': ['/legacy']},
                             {'version': 'v2', 'signature': ['/new']}],
                'required': ['id', 'amount'],
                'rules': [{'target': 'id', 'source': '/entity_id'},
                          {'target': 'amount', 'source': '/legacy/value', 'op': 'scale', 'factor': 100}],
                'errors': {}}
    db = tmp_path / 'db'
    h = engine.freeze(db, contract)
    src = tmp_path / 'x.jsonl'
    src.write_text(json.dumps({'version': 'v1', 'entity_id': 'A', 'subject': 'S',
                               'legacy': {'value': 1}}))
    engine.ingest(db, src, contract)
    engine.translate(db, h)
    assert transactions.reconcile_transactions(db, h) == []
    assert connect(db).execute('SELECT count(*) FROM transaction_record').fetchone()[0] == 0


# --- causal effect on cohort comparison -------------------------------------

def test_per_envelope_legal_but_transaction_unconserved_blocks_cutover(tmp_path):
    db = tmp_path / 'ledger'
    target = tx_contract('direct_debit')
    th = engine.freeze(db, target)
    baseline = json.loads(json.dumps(target))
    baseline['versions'] = [{'version': 'b1', 'signature': ['/baseline_marker']},
                            {'version': 'b2', 'signature': ['/new_event']}]
    bh = engine.freeze(db, baseline)
    # T-100 is healthy; T-200 reuses T-100's credential. Every envelope maps
    # cleanly under both contracts, so per-envelope id/status/amount all match.
    healthy = order_capture('cred-1', txn='T-100')
    reused = order_capture('cred-1', txn='T-200')
    src = tmp_path / 'input.jsonl'
    src.write_text('\n'.join(healthy + reused), encoding='utf-8')
    engine.ingest(db, src, target)
    engine.ingest(db, src, baseline)
    engine.translate(db, th)
    engine.translate(db, bh)
    # Both per-envelope verifications pass on their own.
    assert all(v['status'] == '已核验' for v in engine.verify(db, th))
    assert all(v['status'] == '已核验' for v in engine.verify(db, bh))
    migration.plan(db, 'cutover', bh, th, 0)
    compared = migration.compare(db, 'cutover')
    assert compared['status'] == '待核'
    assert compared['reason'] == 'transaction_unconserved'
    assert all(d['amount_delta'] == 0 for d in compared['diffs'])
    pending_envelopes = {d['envelope_id'] for d in compared['diffs']
                         if d['reason'] == 'transaction_unconserved'}
    assert pending_envelopes  # the unconserved chain holds the cohort back


def test_healthy_transaction_cohort_is_switchable(tmp_path):
    db = tmp_path / 'ledger'
    target = tx_contract('direct_debit')
    th = engine.freeze(db, target)
    baseline = json.loads(json.dumps(target))
    baseline['versions'] = [{'version': 'b1', 'signature': ['/baseline_marker']},
                            {'version': 'b2', 'signature': ['/new_event']}]
    bh = engine.freeze(db, baseline)
    src = tmp_path / 'input.jsonl'
    src.write_text('\n'.join(order_capture('cred-1')), encoding='utf-8')
    engine.ingest(db, src, target)
    engine.ingest(db, src, baseline)
    engine.translate(db, th)
    engine.translate(db, bh)
    migration.plan(db, 'cutover', bh, th, 0)
    compared = migration.compare(db, 'cutover')
    assert compared['status'] == '可切换'
    assert compared['reason'] == 'cohort_compatible'


def test_report_exposes_cross_interface_evidence_chain(tmp_path):
    db, _, h = build(tmp_path, 'direct_debit',
                     order_capture('cred-1') + [
                         env('REF-1', 'refund', 30, 'k-refund', '2026-01-02T08:00:00Z')])
    path = engine.report(db, h, tmp_path / 'report.json')
    report = json.loads(path.read_text(encoding='utf-8'))
    assert len(report['transactions']) == 1
    txn = report['transactions'][0]
    assert [e['event'] for e in txn['events']] == ['order', 'capture', 'refund']
    assert all('source_hash' in e and 'envelope_id' in e and 'event_key' in e
               for e in txn['events'])
    md = path.with_suffix('.md').read_text(encoding='utf-8')
    assert '跨接口交易核对' in md and '事件链' in md
