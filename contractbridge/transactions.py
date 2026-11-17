"""Declarative cross-interface transaction reconciliation.

Transaction contracts are frozen inside the contract hash: they name the
canonical output fields that carry the transaction id, the business event
type, the business instant, the amount, the direct-debit credential and the
idempotency event key.  Reconstruction therefore consumes the same translated
canonical events produced by :mod:`contractbridge.engine` — no field is read
off the raw envelopes behind the provenance chain.

The per-entity reconcile/translate outputs are never rewritten; every result
lands in the transaction_* tables as an independently traceable verdict.
"""
import json
from .store import connect
from . import engine

CANONICAL_EVENTS = ('order', 'authorize', 'capture', 'refund', 'void')
# Business lifecycle order used only to break ties at the same UTC instant.
LIFECYCLE = {'order': 0, 'authorize': 1, 'capture': 2, 'refund': 3, 'void': 4}
PROTOCOLS = ('preauth', 'direct_debit')
VERIFIED, PENDING = '可核验', '待核'


def validate_transaction_contract(contract):
    """Validate the frozen ``transaction`` section; raise ValueError otherwise."""
    tx = contract.get('transaction')
    if tx is None:
        return None
    protocol = tx.get('protocol')
    if protocol not in PROTOCOLS:
        raise ValueError('transaction_protocol_invalid')
    required_fields = ('transaction_id_field', 'event_field', 'time_field',
                       'amount_field', 'event_id_field')
    if any(not tx.get(name) for name in required_fields):
        raise ValueError('transaction_config_incomplete')
    targets = {rule['target'] for rule in contract['rules']}
    needed = {tx[n] for n in required_fields}
    extra_pointers = tx.get('transaction_id_fields') or []
    if extra_pointers and tx['transaction_id_field'] not in extra_pointers:
        raise ValueError('transaction_pointer_inconsistent')
    needed.update(extra_pointers)
    if protocol == 'direct_debit' and not tx.get('credential_field'):
        raise ValueError('transaction_credential_field_required')
    if tx.get('credential_field'):
        needed.add(tx['credential_field'])
    if not needed.issubset(targets):
        raise ValueError('transaction_field_unmapped')
    required_events = tx.get('required_events') or []
    if not required_events or any(e not in CANONICAL_EVENTS for e in required_events):
        raise ValueError('transaction_required_events_invalid')
    return tx


def _amount(body, field):
    value = body.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def reconcile_transactions(db_path, contract_hash):
    """Rebuild every transaction described by one frozen contract.

    Returns a list of verdict dictionaries.  Re-running the function replaces
    the stored verdict for the contract; outputs, runs and issues are untouched.
    """
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM contract WHERE hash=?', (contract_hash,)).fetchone()
        if not row:
            raise ValueError('unknown_contract')
        contract = json.loads(row['body'])
        tx = validate_transaction_contract(contract)
        with db:
            db.execute('DELETE FROM transaction_gap WHERE transaction_pk IN '
                       '(SELECT id FROM transaction_record WHERE contract_id=?)', (row['id'],))
            db.execute('DELETE FROM transaction_event WHERE transaction_pk IN '
                       '(SELECT id FROM transaction_record WHERE contract_id=?)', (row['id'],))
            db.execute('DELETE FROM transaction_record WHERE contract_id=?', (row['id'],))
        if tx is None:
            return []

        id_field, event_field = tx['transaction_id_field'], tx['event_field']
        time_field, amount_field = tx['time_field'], tx['amount_field']
        key_field, cred_field = tx['event_id_field'], tx.get('credential_field')
        id_fields = tx.get('transaction_id_fields') or [id_field]
        required_events = list(tx['required_events'])
        protocol = tx['protocol']

        verify_index = {v['id']: v for v in engine.verify(db_path, contract_hash)}
        outputs = [dict(r) for r in db.execute('''SELECT o.*,e.id AS eid FROM output o
            JOIN run r ON r.id=o.run_id JOIN envelope e ON e.id=o.envelope_id
            WHERE r.contract_id=? ORDER BY o.id''', (row['id'],))]

        groups, unattached = {}, []
        # Credentials are non-reusable across the whole contract: build a
        # contract-wide owner map before any single transaction is judged.
        credential_index = {}
        # One canonical event may legitimately carry several raw transaction id
        # pointers; different ids on the same output are ambiguous evidence.
        for out in outputs:
            body = json.loads(out['body'])
            verdict = verify_index.get(out['id'])
            if verdict and verdict['status'] != '已核验':
                unattached.append({'output_id': out['id'], 'code': 'output_unverified',
                                   'detail': f"output {out['id']} verify={verdict['status']}"})
                continue
            pointer_values = {body.get(name) for name in id_fields
                              if body.get(name) not in (None, '')}
            if len(pointer_values) > 1:
                unattached.append({'output_id': out['id'], 'code': 'transaction_id_ambiguous',
                                   'detail': f'pointers {sorted(map(str, pointer_values))} disagree'})
                continue
            tx_id = body.get(id_field)
            if tx_id in (None, ''):
                unattached.append({'output_id': out['id'], 'code': 'transaction_id_missing',
                                   'detail': f"field {id_field} absent on output {out['id']}"})
                continue
            tx_id = str(tx_id)
            groups.setdefault(tx_id, []).append((out, body))
            if cred_field and body.get(cred_field):
                credential_index.setdefault(body[cred_field], set()).add(tx_id)
        reused_credentials = {c for c, owners in credential_index.items() if len(owners) > 1}

        results = []
        for tx_id in sorted(groups):
            members = groups[tx_id]
            gaps, events = [], []
            seen_keys = {}
            local_credentials = {}
            for out, body in members:
                event = body.get(event_field)
                amount_value = _amount(body, amount_field)
                instant = body.get(time_field)
                event_key = body.get(key_field)
                credential = body.get(cred_field) if cred_field else None
                base = {'output_id': out['id'], 'envelope_id': out['eid'], 'event': event,
                        'amount': amount_value, 'event_time': instant, 'event_key': event_key,
                        'credential': credential}
                if event not in CANONICAL_EVENTS:
                    gaps.append({'output_id': out['id'], 'code': 'event_unknown',
                                 'detail': f'{event_field}={event!r}'})
                    continue
                if amount_value is None:
                    gaps.append({'output_id': out['id'], 'code': 'amount_invalid',
                                 'detail': f'{amount_field}={body.get(amount_field)!r}'})
                    continue
                if amount_value < 0:
                    gaps.append({'output_id': out['id'], 'code': 'amount_negative',
                                 'detail': str(amount_value)})
                    continue
                if not instant:
                    gaps.append({'output_id': out['id'], 'code': 'event_time_missing',
                                 'detail': f'{time_field} absent'})
                    continue
                if event_key in (None, ''):
                    gaps.append({'output_id': out['id'], 'code': 'event_key_missing',
                                 'detail': f'{key_field} absent'})
                    continue
                # Replay handling: same business event key repeats.  Exact replays
                # are idempotent and never counted twice; conflicting replays break
                # conservation convergence.
                if event_key in seen_keys:
                    prior = seen_keys[event_key]
                    # Replay identity is the business payload; envelope entity
                    # ids (source packaging) deliberately do not participate.
                    # Compare the raw instant string, not parsed datetimes.
                    if (prior['event'], prior['amount'], prior['event_time'], prior['credential']) == \
                            (event, amount_value, instant, credential):
                        prior['replay_count'] += 1
                        continue
                    gaps.append({'output_id': out['id'], 'code': 'replay_conflict',
                                 'detail': f'event_key={event_key} replayed with different payload'})
                    continue
                try:
                    parsed = engine.event_instant(instant)
                except (ValueError, TypeError):
                    gaps.append({'output_id': out['id'], 'code': 'event_time_invalid',
                                 'detail': f'{time_field}={instant!r}'})
                    continue
                record = dict(base, instant=parsed, replay_count=1)
                seen_keys[event_key] = record
                events.append(record)
                if credential and (credential in reused_credentials or
                                   credential in local_credentials):
                    if credential in reused_credentials:
                        detail = (f'credential reused across transactions '
                                  f'{sorted(credential_index[credential])}')
                    else:
                        detail = f'credential reused by outputs {local_credentials[credential]} and {out["id"]}'
                    gaps.append({'output_id': out['id'], 'code': 'credential_reused',
                                 'detail': detail})
                elif credential:
                    local_credentials[credential] = out['id']

            balances = _walk(events, protocol, gaps)

            present = {e['event'] for e in events}
            for needed in required_events:
                if needed not in present:
                    gaps.append({'output_id': None, 'code': 'required_interface_missing',
                                 'detail': f'no {needed} event for transaction {tx_id}'})
            if protocol == 'preauth' and 'authorize' not in present and 'capture' in present:
                gaps.append({'output_id': None, 'code': 'authorization_missing',
                             'detail': 'preauth protocol requires authorization before capture'})
            if protocol == 'direct_debit':
                captures = [e for e in events if e['event'] == 'capture']
                if not captures:
                    gaps.append({'output_id': None, 'code': 'direct_debit_credential_missing',
                                 'detail': 'direct debit requires a capture event'})
                elif any(not e['credential'] for e in captures):
                    gaps.append({'output_id': None, 'code': 'direct_debit_credential_missing',
                                 'detail': 'capture carries no non-reusable credential'})

            status = PENDING if gaps else VERIFIED
            with db:
                pk = db.execute('''INSERT INTO transaction_record
                    (contract_id,transaction_id,protocol,status,order_amount,authorized,captured,
                     refunded,voided,refundable) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (row['id'], tx_id, protocol, status, balances['order'], balances['authorized'],
                     balances['captured'], balances['refunded'], balances['voided'],
                     balances['refundable'])).lastrowid
                for ordinal, e in enumerate(sorted(events, key=lambda x: (x['instant'],
                                                                          LIFECYCLE[x['event']],
                                                                          x['output_id'])), 1):
                    db.execute('''INSERT INTO transaction_event
                        (transaction_pk,output_id,envelope_id,event,amount,event_time,event_key,
                         credential,ordinal,replay_count) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                        (pk, e['output_id'], e['envelope_id'], e['event'], e['amount'],
                         e['event_time'], e['event_key'], e['credential'], ordinal,
                         e['replay_count']))
                seen_gap = set()
                for gap in gaps:
                    signature = (gap['output_id'], gap['code'], gap['detail'])
                    if signature in seen_gap:
                        continue
                    seen_gap.add(signature)
                    db.execute('INSERT INTO transaction_gap(transaction_pk,output_id,code,detail) VALUES (?,?,?,?)',
                               (pk, gap['output_id'], gap['code'], gap['detail']))
            results.append({'transaction_id': tx_id, 'protocol': protocol, 'status': status,
                            'balances': {k: balances[k] for k in
                                         ('order', 'authorized', 'captured', 'refunded',
                                          'voided', 'refundable')},
                            'gaps': gaps, 'event_count': len(events)})

        with db:
            for item in unattached:
                db.execute('INSERT INTO transaction_gap(transaction_pk,output_id,code,detail) VALUES (NULL,?,?,?)',
                           (item['output_id'], item['code'], item['detail']))
        for item in results:
            item['unattached'] = [u for u in unattached]
        return results
    finally:
        db.close()


def _walk(events, protocol, gaps):
    """Replay events in business-time order and enforce amount conservation."""
    balances = {'order': 0.0, 'authorized': 0.0, 'captured': 0.0,
                'refunded': 0.0, 'voided': 0.0, 'refundable': 0.0}
    ordered = sorted(events, key=lambda e: (e['instant'], LIFECYCLE[e['event']], e['output_id']))
    for e in ordered:
        kind, amount, oid = e['event'], e['amount'], e['output_id']
        if kind == 'order':
            balances['order'] += amount
        elif kind == 'authorize':
            balances['authorized'] += amount
        elif kind == 'capture':
            # Preauth always needs enough authorization; direct debit may have
            # no authorization event, but a partial authorization still caps it.
            if amount > balances['authorized'] + 1e-9 and \
                    (protocol == 'preauth' or balances['authorized'] > 0):
                gaps.append({'output_id': oid, 'code': 'capture_exceeds_authorization',
                             'detail': f'capture {amount} > authorized {balances["authorized"]}'})
            balances['captured'] += amount
        elif kind == 'refund':
            available = balances['captured'] - balances['refunded']
            if amount > available + 1e-9:
                gaps.append({'output_id': oid, 'code': 'refund_exceeds_captured',
                             'detail': f'refund {amount} > refundable {available}'})
            balances['refunded'] += amount
        elif kind == 'void':
            balances['voided'] += amount
        balances['refundable'] = max(balances['captured'] - balances['refunded'], 0.0)
    return balances


def pending_outputs(db_path, contract_hash):
    """Output ids whose transaction-level verdict is not 可核验 (or unattached)."""
    db = connect(db_path)
    try:
        row = db.execute('SELECT id FROM contract WHERE hash=?', (contract_hash,)).fetchone()
        if not row:
            return set()
        ids = {r[0] for r in db.execute('''SELECT te.output_id FROM transaction_event te
            JOIN transaction_record tr ON tr.id=te.transaction_pk
            WHERE tr.contract_id=? AND tr.status=?''', (row['id'], PENDING))}
        ids |= {r[0] for r in db.execute('''SELECT tg.output_id FROM transaction_gap tg
            JOIN transaction_record tr ON tr.id=tg.transaction_pk
            WHERE tr.contract_id=? AND tg.output_id IS NOT NULL''', (row['id'],))}
        ids |= {r[0] for r in db.execute('''SELECT output_id FROM transaction_gap
            WHERE transaction_pk IS NULL AND output_id IS NOT NULL''')}
        return ids
    finally:
        db.close()
