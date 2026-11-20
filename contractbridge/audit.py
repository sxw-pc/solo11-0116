"""Freeze an auditor's requested evidence scope, then issue offline-verifiable packets."""
import codecs
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from .engine import (LineSplitter, canonical, cross_verdicts, gate_step,
                     identify, normalize_identity, sha, transform)
from .store import connect, snapshot

SCHEMA = """CREATE TABLE IF NOT EXISTS audit_request(
    id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL,
    source_ids TEXT NOT NULL, purpose TEXT NOT NULL,
    request_sha TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_issuance(
    request_id TEXT NOT NULL, policy TEXT NOT NULL,
    packet_id TEXT NOT NULL, packet_sha TEXT NOT NULL,
    status TEXT NOT NULL, counts TEXT NOT NULL, path TEXT NOT NULL,
    created TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(request_id, policy));
"""

POLICIES = ('strict_clean', 'exceptions_attested')
ISSUED = '已签发'
ISSUED_WITH_EXCEPTIONS = '已签发但含例外'
REFUSED = '不可签发'
STATUSES = (ISSUED, ISSUED_WITH_EXCEPTIONS, REFUSED)
CATEGORIES = ('verified', 'pending', 'parse_error', 'version_unknown',
              'output_missing', 'output_duplicate', 'tampered')
EXCEPTION_CATEGORIES = ('pending', 'parse_error', 'version_unknown')
INTEGRITY_CATEGORIES = ('output_missing', 'output_duplicate', 'tampered')
FORMAT = 'contractbridge.audit.v1'
REFERENCE_FIELDS = ('envelope_id', 'source_id', 'line_no', 'entity_id',
                    'subject', 'event_time', 'state', 'raw_sha256')


def request(db_path, request_id, contract_hash, source_ids, purpose):
    if (not request_id or not contract_hash or not purpose or
            not isinstance(source_ids, list) or not source_ids or
            any(not isinstance(x, int) or isinstance(x, bool) or x <= 0 for x in source_ids) or
            len(set(source_ids)) != len(source_ids)):
        raise ValueError('invalid_audit_request')
    source_ids = sorted(source_ids)
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM contract WHERE hash=?', (contract_hash,)).fetchone():
            raise ValueError('unknown_contract')
        for source_id in source_ids:
            if not db.execute('SELECT 1 FROM source WHERE id=?', (source_id,)).fetchone():
                raise ValueError('unknown_source')
        body = json.dumps({'id': request_id, 'contract_hash': contract_hash,
                           'source_ids': source_ids, 'purpose': purpose},
                          ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(body.encode()).hexdigest()
        with db:
            old = db.execute('SELECT request_sha FROM audit_request WHERE id=?', (request_id,)).fetchone()
            if old and old['request_sha'] != digest:
                raise ValueError('audit_request_conflict')
            db.execute('INSERT OR IGNORE INTO audit_request VALUES (?,?,?,?,?)',
                       (request_id, contract_hash, json.dumps(source_ids), purpose, digest))
        return {'id': request_id, 'request_sha': digest}
    finally:
        db.close()


def describe(db_path, request_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM audit_request WHERE id=?', (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_audit_request')
        item = dict(row)
        item['source_ids'] = json.loads(item['source_ids'])
        return item
    finally:
        db.close()


def _slug(text):
    return re.sub(r'[^0-9A-Za-z_.-]+', '-', str(text)) or 'packet'


def _replay_line(line_text, contract):
    """Stateless per-line replay: JSON decode, version identity, translation."""
    replay = {'parse_error': None, 'version': None, 'entity_id': None,
              'envelope_status': None, 'output': None, 'output_sha256': None,
              'evidence': [], 'transform_issues': []}
    try:
        obj = json.loads(line_text)
    except ValueError as exc:
        replay['parse_error'] = str(exc)
        return replay
    if not isinstance(obj, dict):
        replay['parse_error'] = 'envelope is not a JSON object'
        return replay
    replay['version'] = identify(obj, contract)
    replay['entity_id'] = normalize_identity(obj, contract)
    replay['envelope_status'] = '已识别版本' if replay['version'] else '待核'
    if replay['version']:
        obj = dict(obj)
        obj['entity_id'] = replay['entity_id']
        output, evidence, issues = transform(obj, contract)
        replay['output'] = output
        replay['output_sha256'] = sha(canonical(output).encode())
        replay['evidence'] = [list(x) for x in evidence]
        replay['transform_issues'] = [list(x) for x in issues]
    return replay


def _tuples(rows):
    return Counter(tuple(x) for x in rows)


def _classify(line_text, contract, envelope, outputs, stored_issues, gate, cross, replay=None):
    """Classify one raw line against stored artifacts into exactly one category.

    Pure: the issuer feeds database rows, the offline verifier feeds packet
    claims; both must reach the same category, findings and expectations."""
    replay = replay if replay is not None else _replay_line(line_text, contract)
    findings = []
    result = {'replay': replay, 'category': None, 'findings': findings, 'exception': None,
              'expected_issues': [], 'expected_output_status': None,
              'gate_skip': bool(gate and gate.get('skip'))}
    line_sha = sha(line_text.encode('utf-8'))
    if replay['parse_error'] is not None:
        if envelope is not None:
            findings.append(('phantom_envelope', f"envelope {envelope.get('id')} exists for unparsable line"))
        if outputs:
            findings.append(('output_unexpected', f'{len(outputs)} output(s) for unparsable line'))
        if stored_issues:
            findings.append(('issue_unexpected', f'{len(stored_issues)} issue(s) bound to unparsable line'))
        result['category'] = 'tampered' if findings else 'parse_error'
        if not findings:
            result['exception'] = {'reason': 'parse_error', 'detail': replay['parse_error']}
        return result
    if envelope is None:
        findings.append(('envelope_missing', 'no envelope row for parsable line'))
        result['category'] = 'tampered'
        return result
    if envelope.get('raw_sha256') != line_sha:
        findings.append(('envelope_raw_mismatch', f"envelope {envelope.get('id')} raw differs from source line"))
    if envelope.get('version') != replay['version']:
        findings.append(('envelope_version_mismatch',
                         f"envelope {envelope.get('id')} version {envelope.get('version')!r} != replayed {replay['version']!r}"))
    expected_estatus = '已识别版本' if replay['version'] else '待核'
    if envelope.get('status') != expected_estatus:
        findings.append(('envelope_status_mismatch',
                         f"envelope {envelope.get('id')} status {envelope.get('status')!r} != expected {expected_estatus!r}"))
    if (envelope.get('entity_id') or '') != (replay['entity_id'] or ''):
        findings.append(('envelope_entity_mismatch',
                         f"envelope {envelope.get('id')} entity_id differs from replay"))
    if replay['version'] is None:
        expected = [('version_ambiguous', line_text)]
        result['expected_issues'] = [list(x) for x in expected]
        if outputs:
            findings.append(('output_unexpected', f'{len(outputs)} output(s) for versionless line'))
        if _tuples(stored_issues) != _tuples(expected):
            findings.append(('issue_mismatch', 'stored issues differ from replayed version_ambiguous'))
        result['category'] = 'tampered' if findings else 'version_unknown'
        if not findings:
            result['exception'] = {'reason': 'version_unknown', 'detail': 'version not identifiable'}
        return result
    gate = gate or {'skip': False, 'issues': []}
    gate_issues = [tuple(x) for x in gate.get('issues') or []]
    cross_issues = [tuple(x) for x in cross or []]
    if gate.get('skip'):
        expected = gate_issues + cross_issues
        result['expected_issues'] = [list(x) for x in expected]
        if outputs:
            findings.append(('output_unexpected', f'{len(outputs)} output(s) for identity-blocked line'))
        if _tuples(stored_issues) != _tuples(expected):
            findings.append(('issue_mismatch', 'stored issues differ from replayed gate/cross issues'))
        result['category'] = 'tampered' if findings else 'pending'
        if not findings:
            reason = expected[0][0] if expected else 'identity_gate'
            result['exception'] = {'reason': reason,
                                   'detail': '; '.join(f'{c}:{d}' for c, d in expected) or reason}
        return result
    expected = gate_issues + [tuple(x) for x in replay['transform_issues']] + cross_issues
    result['expected_issues'] = [list(x) for x in expected]
    expected_status = '待核' if (replay['transform_issues'] or cross_issues) else '已核验'
    result['expected_output_status'] = expected_status
    if not outputs:
        findings.append(('output_missing', 'no output row for translated line'))
        if _tuples(stored_issues) != _tuples(expected):
            findings.append(('issue_mismatch', 'stored issues differ from replayed issues'))
        result['category'] = 'output_missing'
        return result
    if len(outputs) > 1:
        findings.append(('output_duplicate',
                         f"{len(outputs)} outputs for one envelope: {[o.get('id') for o in outputs]}"))
        result['category'] = 'output_duplicate'
        return result
    output = outputs[0]
    if output.get('hash') != sha((output.get('body') or '').encode('utf-8')):
        findings.append(('output_hash_mismatch', f"output {output.get('id')} hash does not match its body"))
    if output.get('body') != canonical(replay['output']):
        findings.append(('output_business_mismatch',
                         f"output {output.get('id')} body differs from source-line replay"))
    if _tuples(output.get('evidence') or []) != _tuples(replay['evidence']):
        findings.append(('evidence_mismatch', f"output {output.get('id')} field evidence differs from replay"))
    if output.get('status') != expected_status:
        findings.append(('output_status_mismatch',
                         f"output {output.get('id')} status {output.get('status')!r} != replayed {expected_status!r}"))
    if _tuples(stored_issues) != _tuples(expected):
        findings.append(('issue_mismatch', 'stored issues differ from replayed issues'))
    if findings:
        result['category'] = 'tampered'
    elif expected_status == '已核验' and not expected:
        result['category'] = 'verified'
    else:
        result['category'] = 'pending'
        result['exception'] = {'reason': expected[0][0],
                               'detail': '; '.join(f'{c}:{d}' for c, d in expected)}
    return result


class _ShardWriter:
    """Buffered deterministic shard writer: flushes fixed-size canonical JSONL shards."""

    def __init__(self, folder, prefix, size):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.prefix = prefix
        self.size = size
        self.buf = []
        self.shards = []

    def add(self, record):
        self.buf.append(record)
        if len(self.buf) >= self.size:
            self.flush()

    def flush(self):
        if not self.buf:
            return
        name = f'{self.prefix}-{len(self.shards) + 1:06d}.jsonl'
        data = ''.join(canonical(r) + '\n' for r in self.buf).encode('utf-8')
        (self.folder / name).write_bytes(data)
        self.shards.append({'path': f'{self.folder.name}/{name}',
                            'sha256': sha(data), 'records': len(self.buf)})
        self.buf = []


class _JsonlSink:
    """Streaming canonical JSONL writer with running digest and record count."""

    def __init__(self, path):
        self.path = Path(path)
        self.digest = hashlib.sha256()
        self.count = 0
        self.handle = open(self.path, 'wb')

    def add(self, record):
        data = (canonical(record) + '\n').encode('utf-8')
        self.digest.update(data)
        self.handle.write(data)
        self.count += 1

    def close(self):
        self.handle.close()
        return {'path': self.path.name, 'sha256': self.digest.hexdigest(), 'records': self.count}


def _empty_counts():
    counts = {key: 0 for key in CATEGORIES}
    counts.update({'total_lines': 0, 'exceptions': 0, 'line_findings': 0,
                   'packet_findings': 0, 'references': 0})
    return counts


def _build(db_path, request_data, policy, tmp_dir, shard_size):
    """Replay the frozen request scope inside one snapshot and write the packet tree."""
    tmp = Path(tmp_dir)
    (tmp / 'sources').mkdir(parents=True, exist_ok=True)
    source_ids = list(request_data['source_ids'])
    source_set = set(source_ids)
    marks = ','.join('?' * len(source_ids))
    packet_id = f"{_slug(request_data['id'])}.{policy}"
    findings = _JsonlSink(tmp / 'findings.jsonl')
    references = _JsonlSink(tmp / 'references.jsonl')
    counterexamples = _JsonlSink(tmp / 'counterexamples.jsonl')
    counts = _empty_counts()

    def packet_finding(code, detail, **ctx):
        counts['packet_findings'] += 1
        findings.add({'code': code, 'detail': detail, **ctx})

    snap = snapshot(db_path)
    try:
        contract_row = snap.execute('SELECT * FROM contract WHERE hash=?',
                                    (request_data['contract_hash'],)).fetchone()
        if not contract_row:
            raise ValueError('unknown_contract')
        body = contract_row['body']
        contract_body = body.encode('utf-8') if isinstance(body, str) else bytes(body)
        if sha(contract_body) != request_data['contract_hash']:
            packet_finding('contract_hash_mismatch', 'contract body does not match frozen hash')
        contract = json.loads(contract_body)
        (tmp / 'contract.json').write_bytes(contract_body)
        contract_id = contract_row['id']
        # Bounded scratch tables: replay state spills to disk instead of memory.
        snap.execute(f'CREATE TEMP TABLE t_env AS SELECT * FROM envelope WHERE source_id IN ({marks})',
                     source_ids)
        snap.execute('CREATE INDEX t_env_idx ON t_env(source_id,line_no)')
        snap.execute(f'''CREATE TEMP TABLE t_out AS SELECT o.id,o.envelope_id,o.run_id,o.body,o.hash,o.status
            FROM output o JOIN run r ON r.id=o.run_id
            WHERE r.contract_id=? AND r.source_id IN ({marks})''', [contract_id] + source_ids)
        snap.execute('CREATE INDEX t_out_idx ON t_out(envelope_id)')
        snap.execute('''CREATE TEMP TABLE t_evi AS SELECT e.output_id,e.field,e.pointer,e.rule
            FROM evidence e WHERE e.output_id IN (SELECT id FROM t_out)''')
        snap.execute('CREATE INDEX t_evi_idx ON t_evi(output_id)')
        snap.execute(f'''CREATE TEMP TABLE t_iss AS SELECT i.id,i.envelope_id,i.run_id,i.code,i.detail
            FROM issue i WHERE i.envelope_id IN (SELECT id FROM t_env)
            OR i.run_id IN (SELECT id FROM run WHERE contract_id=? AND source_id IN ({marks}))''',
                     [contract_id] + source_ids)
        snap.execute('CREATE INDEX t_iss_idx ON t_iss(envelope_id)')
        snap.execute('CREATE TEMP TABLE t_gate(envelope_id INTEGER PRIMARY KEY,skip INT)')
        snap.execute('CREATE TEMP TABLE t_gate_iss(envelope_id INT,code TEXT,detail TEXT)')
        snap.execute('CREATE INDEX t_gate_iss_idx ON t_gate_iss(envelope_id)')
        snap.execute('CREATE TEMP TABLE t_cross(envelope_id INT,code TEXT,detail TEXT)')
        snap.execute('CREATE INDEX t_cross_idx ON t_cross(envelope_id)')
        runs = {}
        for row in snap.execute(f'SELECT * FROM run WHERE contract_id=? AND source_id IN ({marks})',
                                [contract_id] + source_ids):
            runs[row['source_id']] = dict(row)
        # Stateful identity/state gate replay over every run in creation order;
        # the global entity walk makes cross-source conflicts reproducible.
        entities = {}
        in_scope_run_ids = {row['id'] for row in runs.values()}
        for run in snap.execute('SELECT * FROM run ORDER BY id').fetchall():
            seen, states = {}, {}
            scoped = run['id'] in in_scope_run_ids
            gate_rows, gate_issues = [], []
            for env in snap.execute(
                    'SELECT id,version,entity_id,raw FROM envelope WHERE source_id=? ORDER BY line_no',
                    (run['source_id'],)):
                if not env['version']:
                    continue
                try:
                    obj = json.loads(env['raw'])
                    issues, skip = gate_step(obj, env['entity_id'], seen, states, entities)
                except Exception as exc:
                    if scoped:
                        packet_finding('gate_replay_error',
                                       f"envelope {env['id']} gate replay failed: {exc}",
                                       envelope_id=env['id'])
                    continue
                if scoped:
                    gate_rows.append((env['id'], 1 if skip else 0))
                    gate_issues.extend((env['id'], code, detail) for code, detail in issues)
            if gate_rows:
                snap.executemany('INSERT INTO t_gate VALUES (?,?)', gate_rows)
            if gate_issues:
                snap.executemany('INSERT INTO t_gate_iss VALUES (?,?,?)', gate_issues)
        # Cross-package replay over entity groups; out-of-scope members of any
        # group touching the request scope become minimal reference evidence.
        group = []
        current_entity = None

        def flush_group():
            if not group or not any(m['source_id'] in source_set for m in group):
                return
            members = [(m['id'], m['subject'], m['event_time'], m['state']) for m in group]
            try:
                verdicts = cross_verdicts(members)
            except Exception as exc:
                packet_finding('cross_replay_error',
                               f"entity {group[0]['entity_id']} cross-package replay failed: {exc}")
                return
            verdict_map = {}
            for envelope_id, code in verdicts:
                verdict_map.setdefault(envelope_id, []).append(code)
            for member in group:
                if member['source_id'] in source_set:
                    for code in verdict_map.get(member['id'], []):
                        snap.execute('INSERT INTO t_cross VALUES (?,?,?)',
                                     (member['id'], code, member['entity_id']))
                else:
                    references.add({key: member[key] for key in REFERENCE_FIELDS})
                    counts['references'] += 1

        for env in snap.execute('''SELECT id,source_id,line_no,entity_id,raw FROM envelope
                WHERE version IS NOT NULL AND entity_id IS NOT NULL AND entity_id<>''
                ORDER BY entity_id,id'''):
            try:
                obj = json.loads(env['raw'])
            except ValueError:
                continue
            member = {'id': env['id'], 'source_id': env['source_id'], 'line_no': env['line_no'],
                      'entity_id': env['entity_id'], 'subject': str(obj.get('subject', '')),
                      'event_time': obj.get('event_time'), 'state': obj.get('state'),
                      'envelope_id': env['id'], 'raw_sha256': sha(env['raw'].encode('utf-8'))}
            if current_entity is not None and member['entity_id'] != current_entity:
                flush_group()
                group = []
            current_entity = member['entity_id']
            group.append(member)
        flush_group()
        # Per-line pass: stream source bytes, classify every line, shard records.
        shards = _ShardWriter(tmp / 'lines', 'lines', shard_size)
        sources_meta = []
        seq = 0
        run_state = {row['id']: {'bad': False, 'cross_upgrade': False} for row in runs.values()}
        for sid in source_ids:
            src = snap.execute('SELECT id,hash,length(body) AS blen FROM source WHERE id=?',
                               (sid,)).fetchone()
            if not src:
                packet_finding('source_missing', f'source {sid} not found', source_id=sid)
                continue
            src_rel = f'sources/src-{sid}.jsonl'
            body_hash = hashlib.sha256()
            nbytes = 0
            decoder = codecs.getincrementaldecoder('utf-8')()
            splitter = LineSplitter()
            line_count = 0
            decode_failed = False
            env_cursor = snap.execute('SELECT * FROM t_env WHERE source_id=? ORDER BY line_no', (sid,))
            env_rows = iter(env_cursor.fetchone, None)
            pending = next(env_rows, None)

            def take_envelope(line_no):
                nonlocal pending
                envelope = None
                while pending is not None:
                    line_no_stored = pending['line_no']
                    if line_no_stored is None or line_no_stored < line_no:
                        packet_finding('phantom_envelope',
                                       f"envelope {pending['id']} line_no {line_no_stored} has no source line",
                                       envelope_id=pending['id'], source_id=sid)
                        pending = next(env_rows, None)
                        continue
                    if line_no_stored == line_no:
                        envelope = pending
                        pending = next(env_rows, None)
                    break
                return envelope

            def handle_line(line_no, offset, length, text):
                nonlocal seq, line_count
                line_count += 1
                seq += 1
                envelope = take_envelope(line_no)
                run = runs.get(sid)
                envelope_norm = None
                outputs, stored, gate, cross = [], [], None, []
                if envelope is not None:
                    raw = envelope['raw']
                    envelope_norm = {'id': envelope['id'], 'version': envelope['version'],
                                     'status': envelope['status'], 'entity_id': envelope['entity_id'],
                                     'raw_sha256': sha(raw.encode('utf-8')) if raw is not None else None}
                    outputs = [{'id': o['id'], 'hash': o['hash'], 'status': o['status'], 'body': o['body'],
                                'evidence': [[e['field'], e['pointer'], e['rule']] for e in snap.execute(
                                    'SELECT field,pointer,rule FROM t_evi WHERE output_id=? ORDER BY field',
                                    (o['id'],))]}
                               for o in snap.execute('SELECT * FROM t_out WHERE envelope_id=? ORDER BY id',
                                                      (envelope['id'],))]
                    stored = [[i['code'], i['detail']] for i in snap.execute(
                        'SELECT code,detail FROM t_iss WHERE envelope_id=? ORDER BY id', (envelope['id'],))]
                    gate_row = snap.execute('SELECT skip FROM t_gate WHERE envelope_id=?',
                                            (envelope['id'],)).fetchone()
                    if gate_row is not None:
                        gate = {'skip': bool(gate_row['skip']),
                                'issues': [[g['code'], g['detail']] for g in snap.execute(
                                    'SELECT code,detail FROM t_gate_iss WHERE envelope_id=? ORDER BY rowid',
                                    (envelope['id'],))]}
                    cross = [[c['code'], c['detail']] for c in snap.execute(
                        'SELECT code,detail FROM t_cross WHERE envelope_id=? ORDER BY rowid', (envelope['id'],))]
                replay = _replay_line(text, contract)
                result = _classify(text, contract, envelope_norm, outputs, stored, gate, cross, replay=replay)
                counts[result['category']] += 1
                counts['total_lines'] += 1
                counts['line_findings'] += len(result['findings'])
                if result['category'] in EXCEPTION_CATEGORIES:
                    counts['exceptions'] += 1
                record = {'seq': seq, 'source_id': sid, 'line_no': line_no,
                          'offset': offset, 'length': length,
                          'line_sha256': sha(text.encode('utf-8')),
                          'category': result['category'],
                          'envelope': envelope_norm,
                          'run': ({'id': run['id'], 'status': run['status'],
                                   'contract_hash': request_data['contract_hash']} if run else None),
                          'outputs': outputs, 'stored_issues': stored,
                          'replayed': {'parse_error': replay['parse_error'],
                                       'version': replay['version'],
                                       'entity_id': replay['entity_id'],
                                       'envelope_status': replay['envelope_status'],
                                       'output_sha256': replay['output_sha256'],
                                       'transform_issues': replay['transform_issues'],
                                       'gate_skip': bool(gate and gate['skip']),
                                       'gate_issues': (gate['issues'] if gate else []),
                                       'cross_issues': cross,
                                       'expected_output_status': result['expected_output_status']},
                          'findings': [{'code': code, 'detail': detail}
                                       for code, detail in result['findings']],
                          'exception': result['exception']}
                shards.add(record)
                if result['category'] != 'verified' or result['findings']:
                    counterexamples.add(record)
                if run is not None and envelope is not None:
                    state = run_state[run['id']]
                    if (replay['version'] is None or (gate and gate['issues'])
                            or replay['transform_issues']):
                        state['bad'] = True
                    if cross and outputs:
                        state['cross_upgrade'] = True

            blob = snap.blobopen('source', 'body', sid)
            try:
                with open(tmp / src_rel, 'wb') as out:
                    while True:
                        chunk = blob.read(65536)
                        if not chunk:
                            break
                        body_hash.update(chunk)
                        nbytes += len(chunk)
                        out.write(chunk)
                        if not decode_failed:
                            try:
                                for span in splitter.feed(decoder.decode(chunk)):
                                    handle_line(*span)
                            except ValueError:
                                decode_failed = True
                                packet_finding('source_undecodable',
                                               f'source {sid} body is not valid UTF-8', source_id=sid)
                    if not decode_failed:
                        try:
                            for span in splitter.feed(decoder.decode(b'', final=True)):
                                handle_line(*span)
                            for span in splitter.finish():
                                handle_line(*span)
                        except ValueError:
                            decode_failed = True
                            packet_finding('source_undecodable',
                                           f'source {sid} body is not valid UTF-8', source_id=sid)
            finally:
                blob.close()
            while pending is not None:
                packet_finding('phantom_envelope',
                               f"envelope {pending['id']} line_no {pending['line_no']} has no source line",
                               envelope_id=pending['id'], source_id=sid)
                pending = next(env_rows, None)
            if body_hash.hexdigest() != src['hash']:
                packet_finding('source_hash_mismatch',
                               f'source {sid} body hash differs from frozen hash', source_id=sid)
            sources_meta.append({'source_id': sid, 'path': src_rel,
                                 'sha256': body_hash.hexdigest(), 'bytes': nbytes,
                                 'lines': line_count})
        shards.flush()
        for sid, run in runs.items():
            state = run_state[run['id']]
            expected = '待核' if (state['bad'] or state['cross_upgrade']) else '已核验'
            if run['status'] != expected:
                packet_finding('run_status_mismatch',
                               f"run {run['id']} status {run['status']!r} != replayed {expected!r}",
                               run_id=run['id'], source_id=sid)
        for sid in source_ids:
            if sid not in runs and any(m['source_id'] == sid for m in sources_meta):
                packet_finding('run_missing', f'no run for source {sid} and this contract',
                               source_id=sid)
        for issue_row in snap.execute('SELECT * FROM t_iss WHERE envelope_id IS NULL ORDER BY id'):
            packet_finding('unattributed_issue',
                           f"issue {issue_row['id']} ({issue_row['code']}) bound to run but no envelope",
                           issue_id=issue_row['id'], run_id=issue_row['run_id'])
        for issue_row in snap.execute(
                'SELECT * FROM t_iss WHERE envelope_id IS NOT NULL AND envelope_id NOT IN (SELECT id FROM t_env)'):
            packet_finding('foreign_envelope_issue',
                           f"issue {issue_row['id']} ({issue_row['code']}) points outside the request scope",
                           issue_id=issue_row['id'], envelope_id=issue_row['envelope_id'])
        for orphan in snap.execute(
                'SELECT o.* FROM t_out o LEFT JOIN t_env e ON e.id=o.envelope_id WHERE e.id IS NULL'):
            packet_finding('orphan_output',
                           f"output {orphan['id']} references an envelope outside the request scope",
                           output_id=orphan['id'], envelope_id=orphan['envelope_id'])
        findings_meta = findings.close()
        references_meta = references.close()
        counter_meta = counterexamples.close()
        integrity = (counts['output_missing'] + counts['output_duplicate'] + counts['tampered']
                     + counts['line_findings'] + counts['packet_findings'])
        exceptions = counts['exceptions']
        if policy == 'strict_clean':
            issuable = not integrity and not exceptions
        else:
            issuable = not integrity
        if issuable:
            status = ISSUED_WITH_EXCEPTIONS if exceptions else ISSUED
        else:
            status = REFUSED
        manifest = {'format': FORMAT, 'packet_id': packet_id,
                    'request': {'id': request_data['id'], 'sha': request_data['sha'],
                                'purpose': request_data['purpose'],
                                'contract_hash': request_data['contract_hash'],
                                'source_ids': source_ids},
                    'policy': policy, 'status': status,
                    'contract': {'path': 'contract.json', 'sha256': sha(contract_body),
                                 'hash': request_data['contract_hash']},
                    'sources': sources_meta,
                    'lines': None, 'counterexamples': None, 'references': None,
                    'findings': None, 'counts': counts}
        if issuable:
            manifest['lines'] = {'shards': shards.shards, 'total': counts['total_lines']}
            (tmp / counter_meta['path']).unlink()
            if references_meta['records']:
                manifest['references'] = references_meta
            else:
                (tmp / references_meta['path']).unlink()
            (tmp / findings_meta['path']).unlink()
        else:
            shutil.rmtree(tmp / 'lines')
            if counter_meta['records']:
                manifest['counterexamples'] = counter_meta
            else:
                (tmp / counter_meta['path']).unlink()
            if findings_meta['records']:
                manifest['findings'] = findings_meta
            else:
                (tmp / findings_meta['path']).unlink()
            if references_meta['records']:
                manifest['references'] = references_meta
            else:
                (tmp / references_meta['path']).unlink()
        manifest['packet_sha256'] = sha(canonical(manifest).encode())
        (tmp / 'manifest.json').write_text(canonical(manifest), encoding='utf-8')
        return manifest, counts, status, issuable
    finally:
        snap.close()


def _request_data(row):
    return {'id': row['id'], 'contract_hash': row['contract_hash'],
            'source_ids': json.loads(row['source_ids']), 'purpose': row['purpose'],
            'sha': row['request_sha']}


def _issuance_result(request_id, policy, row):
    return {'request_id': request_id, 'policy': policy, 'status': row['status'],
            'packet_id': row['packet_id'], 'packet_sha256': row['packet_sha'],
            'path': row['path'], 'counts': json.loads(row['counts'])}


def _restore(db_path, request_row, policy, out_dir, record, shard_size):
    """Rebuild a recorded packet whose directory is missing; never rewrite content."""
    tmp = Path(tempfile.mkdtemp(prefix=f".tmp-{record['packet_id']}-", dir=out_dir))
    try:
        manifest, _counts, _status, _issuable = _build(
            db_path, _request_data(request_row), policy, tmp, shard_size)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    if manifest['packet_sha256'] != record['packet_sha']:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError('audit_packet_lost')
    os.rename(tmp, record['path'])


def issue(db_path, request_id, policy, out_dir, shard_size=1000):
    """Issue the frozen audit request once under a policy; later calls return
    the same frozen packet identity and never rewrite the published packet."""
    if policy not in POLICIES:
        raise ValueError('unknown_audit_policy')
    if not isinstance(shard_size, int) or isinstance(shard_size, bool) or shard_size < 1:
        raise ValueError('invalid_shard_size')
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        request_row = db.execute('SELECT * FROM audit_request WHERE id=?', (request_id,)).fetchone()
        if not request_row:
            raise ValueError('unknown_audit_request')
        packet_id = f'{_slug(request_id)}.{policy}'
        old = db.execute('SELECT * FROM audit_issuance WHERE request_id=? AND policy=?',
                         (request_id, policy)).fetchone()
        if old:
            if not Path(old['path']).exists():
                _restore(db_path, request_row, policy, out_dir, old, shard_size)
            return _issuance_result(request_id, policy, old)
        for stale in out_dir.glob(f'.tmp-{packet_id}-*'):
            shutil.rmtree(stale, ignore_errors=True)
        tmp = Path(tempfile.mkdtemp(prefix=f'.tmp-{packet_id}-', dir=out_dir))
        try:
            manifest, counts, status, issuable = _build(
                db_path, _request_data(request_row), policy, tmp, shard_size)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        packet_sha = manifest['packet_sha256']
        final = out_dir / (packet_id if issuable else packet_id + '.diagnostic')
        # Claim the issuance before publishing: the record is the issuance.
        with db:
            db.execute('INSERT OR IGNORE INTO audit_issuance'
                       '(request_id,policy,packet_id,packet_sha,status,counts,path)'
                       ' VALUES (?,?,?,?,?,?,?)',
                       (request_id, policy, packet_id, packet_sha, status,
                        json.dumps(counts, ensure_ascii=False, sort_keys=True), str(final)))
            row = db.execute('SELECT * FROM audit_issuance WHERE request_id=? AND policy=?',
                             (request_id, policy)).fetchone()
        if row['packet_sha'] != packet_sha:
            shutil.rmtree(tmp, ignore_errors=True)
            if not Path(row['path']).exists():
                _restore(db_path, request_row, policy, out_dir, row, shard_size)
            return _issuance_result(request_id, policy, row)
        if final.exists():
            existing = json.loads((final / 'manifest.json').read_text(encoding='utf-8'))
            if existing.get('packet_sha256') != packet_sha:
                raise ValueError('audit_packet_conflict')
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            os.rename(tmp, final)
        return {'request_id': request_id, 'policy': policy, 'status': status,
                'packet_id': packet_id, 'packet_sha256': packet_sha,
                'path': str(final), 'counts': counts}
    finally:
        db.close()


def _read_jsonl(file_path, meta, label, problems):
    items = []
    ok = True
    if not file_path.is_file():
        problems.append(f"missing_file:{meta['path']}")
        return [], False
    digest = hashlib.sha256()
    count = 0
    with open(file_path, 'rb') as handle:
        for raw in handle:
            digest.update(raw)
            count += 1
            try:
                items.append(json.loads(raw))
            except ValueError:
                problems.append(f'{label}_unparsable')
                ok = False
    if digest.hexdigest() != meta.get('sha256'):
        problems.append(f'{label}_digest')
        ok = False
    if count != meta.get('records'):
        problems.append(f'{label}_records')
        ok = False
    return items, ok


def _iter_records(packet_dir, manifest, problems):
    """Yield line records from shards (issued) or counterexamples (refused)."""
    if manifest.get('lines'):
        entries = manifest['lines']['shards']
        label = 'shard'
    elif manifest.get('counterexamples'):
        entries = [manifest['counterexamples']]
        label = 'counterexamples'
    else:
        return
    for entry in entries:
        file_path = packet_dir / entry['path']
        if not file_path.is_file():
            problems.append(f"missing_file:{entry['path']}")
            continue
        digest = hashlib.sha256()
        count = 0
        with open(file_path, 'rb') as handle:
            for raw in handle:
                digest.update(raw)
                count += 1
                try:
                    yield json.loads(raw)
                except ValueError:
                    problems.append(f"record_unparsable:{entry['path']}")
        if digest.hexdigest() != entry.get('sha256'):
            problems.append(f"{label}_digest:{entry['path']}")
        if count != entry.get('records'):
            problems.append(f"{label}_records:{entry['path']}")


def verify_packet(path):
    """Offline verification of an issued packet or refusal diagnostic.

    Never touches the database: checks the manifest against every shard, the
    source raw bytes and line positions, the contract body and hash, replays
    every output and evidence link, and detects missing or foreign items."""
    checks = []
    problems = []

    def check(name, ok, detail=''):
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
        if not ok:
            problems.append(f'{name}:{detail}' if detail else name)

    result = {'ok': False, 'packet_id': None, 'policy': None, 'status': None,
              'checks': checks, 'problems': problems, 'counts': None}
    packet_dir = Path(path)
    manifest_file = packet_dir / 'manifest.json'
    if not manifest_file.is_file():
        problems.append('manifest_missing')
        return result
    try:
        manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    except (ValueError, OSError) as exc:
        problems.append(f'manifest_unreadable:{exc}')
        return result
    result['packet_id'] = manifest.get('packet_id')
    result['policy'] = manifest.get('policy')
    result['status'] = manifest.get('status')
    counts = manifest.get('counts') or {}
    result['counts'] = counts
    body = canonical({key: value for key, value in manifest.items() if key != 'packet_sha256'})
    check('manifest_digest', sha(body.encode('utf-8')) == manifest.get('packet_sha256'),
          'packet_sha256 mismatch')
    request_info = manifest.get('request') or {}
    policy = manifest.get('policy')
    status = manifest.get('status')
    source_ids = request_info.get('source_ids') or []
    check('packet_identity',
          manifest.get('format') == FORMAT and policy in POLICIES and status in STATUSES
          and manifest.get('packet_id') == f"{_slug(request_info.get('id'))}.{policy}",
          'packet identity fields inconsistent')
    expected_sha = sha(canonical({'id': request_info.get('id'),
                                  'contract_hash': request_info.get('contract_hash'),
                                  'source_ids': source_ids,
                                  'purpose': request_info.get('purpose')}).encode('utf-8'))
    check('request_binding', request_info.get('sha') == expected_sha,
          'request digest does not match frozen fields')
    contract = None
    try:
        contract_bytes = (packet_dir / manifest['contract']['path']).read_bytes()
        contract_ok = (sha(contract_bytes) == manifest['contract'].get('sha256')
                       and sha(contract_bytes) == manifest['contract'].get('hash')
                       and manifest['contract'].get('hash') == request_info.get('contract_hash'))
        contract = json.loads(contract_bytes.decode('utf-8'))
        contract_ok = contract_ok and canonical(contract).encode('utf-8') == contract_bytes
        check('contract_integrity', contract_ok, 'contract body or hash mismatch')
    except (OSError, ValueError, KeyError) as exc:
        problems.append(f'contract_unreadable:{exc}')
    if contract is None:
        return result
    source_spans = {}
    sources_ok = True
    for entry in manifest.get('sources') or []:
        file_path = packet_dir / entry['path']
        if not file_path.is_file():
            problems.append(f"missing_file:{entry['path']}")
            sources_ok = False
            continue
        digest = hashlib.sha256()
        nbytes = 0
        spans = []
        splitter = LineSplitter()
        decoder = codecs.getincrementaldecoder('utf-8')()
        decode_ok = True
        with open(file_path, 'rb') as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
                nbytes += len(chunk)
                if decode_ok:
                    try:
                        spans.extend(splitter.feed(decoder.decode(chunk)))
                    except ValueError:
                        decode_ok = False
        if decode_ok:
            try:
                spans.extend(splitter.feed(decoder.decode(b'', final=True)))
                spans.extend(splitter.finish())
            except ValueError:
                decode_ok = False
        if not decode_ok:
            problems.append(f"source_undecodable:{entry['source_id']}")
            sources_ok = False
        if digest.hexdigest() != entry.get('sha256') or nbytes != entry.get('bytes'):
            problems.append(f"source_digest:{entry['source_id']}")
            sources_ok = False
        if len(spans) != entry.get('lines'):
            problems.append(f"source_lines:{entry['source_id']}")
            sources_ok = False
        source_spans[entry['source_id']] = spans
    check('source_integrity', sources_ok, 'source bytes, hashes or line splits mismatch')
    references, ref_ok = ([], True)
    if manifest.get('references'):
        references, ref_ok = _read_jsonl(packet_dir / manifest['references']['path'],
                                         manifest['references'], 'references', problems)
        for ref in references:
            if (not isinstance(ref, dict) or not ref.get('entity_id')
                    or ref.get('source_id') in source_ids):
                problems.append('reference_scope:reference entry invalid or inside request scope')
                ref_ok = False
            if isinstance(ref, dict) and not set(ref) <= set(REFERENCE_FIELDS):
                problems.append('reference_minimality:reference carries more than minimal fields')
                ref_ok = False
    check('references', ref_ok, 'reference evidence inconsistent')
    findings_list, findings_ok = ([], True)
    if manifest.get('findings'):
        findings_list, findings_ok = _read_jsonl(packet_dir / manifest['findings']['path'],
                                                 manifest['findings'], 'findings', problems)
    check('findings_file', findings_ok, 'findings evidence inconsistent')
    issued = status in (ISSUED, ISSUED_WITH_EXCEPTIONS)
    coverage = {sid: {'next': 1, 'spans': spans} for sid, spans in source_spans.items()}
    groups = {}
    seq = 0
    pass1_ok = True

    def locate(record, sequential):
        """Bind a record to its source line; returns (problems, line_text, obj)."""
        sid = record.get('source_id')
        errs = []
        if sid not in source_ids:
            errs.append(f'foreign_source:{sid}')
            return errs, None, None
        cov = coverage.get(sid)
        if cov is None:
            errs.append(f'unknown_source:{sid}')
            return errs, None, None
        spans = cov['spans']
        line_no = record.get('line_no')
        if sequential and line_no != cov['next']:
            errs.append(f'line_order:{sid}:{line_no}')
            return errs, None, None
        if not isinstance(line_no, int) or line_no < 1 or line_no > len(spans):
            errs.append(f'line_out_of_range:{sid}:{line_no}')
            return errs, None, None
        if sequential:
            cov['next'] += 1
        span = spans[line_no - 1]
        if span[1] != record.get('offset') or span[2] != record.get('length'):
            errs.append(f'line_location:{sid}:{line_no}')
        line_text = span[3]
        if sha(line_text.encode('utf-8')) != record.get('line_sha256'):
            errs.append(f'line_digest:{sid}:{line_no}')
            return errs, None, None
        obj = None
        try:
            obj = json.loads(line_text)
        except ValueError:
            obj = None
        return errs, line_text, obj

    def check_replay(record, line_text):
        replay = _replay_line(line_text, contract)
        rep = record.get('replayed') or {}
        errs = []
        for key in ('parse_error', 'version', 'entity_id', 'envelope_status', 'output_sha256'):
            if rep.get(key) != replay[key]:
                errs.append(f'replay_{key}')
        if [list(x) for x in rep.get('transform_issues') or []] != replay['transform_issues']:
            errs.append('replay_transform_issues')
        run = record.get('run')
        if run is not None and run.get('contract_hash') != request_info.get('contract_hash'):
            errs.append('run_contract_mismatch')
        return errs, replay

    def check_classification(record, line_text, replay, cross):
        rep = record.get('replayed') or {}
        gate = {'skip': rep.get('gate_skip'), 'issues': rep.get('gate_issues') or []}
        classified = _classify(line_text, contract, record.get('envelope'),
                               record.get('outputs') or [], record.get('stored_issues') or [],
                               gate, cross, replay=replay)
        errs = []
        if classified['category'] != record.get('category'):
            errs.append('category_mismatch')
        record_findings = [(f.get('code'), f.get('detail')) for f in record.get('findings') or []]
        if classified['findings'] != record_findings:
            errs.append('findings_mismatch')
        if classified['exception'] != record.get('exception'):
            errs.append('exception_mismatch')
        if classified['expected_output_status'] != rep.get('expected_output_status'):
            errs.append('expected_status_mismatch')
        if [list(x) for x in rep.get('cross_issues') or []] != [list(x) for x in cross]:
            errs.append('cross_mismatch')
        category = record.get('category')
        if category not in CATEGORIES:
            errs.append('category_unknown')
        if category in INTEGRITY_CATEGORIES and not record.get('findings'):
            errs.append('integrity_without_findings')
        if category in EXCEPTION_CATEGORIES and (not record.get('exception') or record.get('findings')):
            errs.append('exception_shape')
        if category == 'verified' and (record.get('exception') or record.get('findings')):
            errs.append('verified_shape')
        return errs, classified

    counted = _empty_counts()
    counted['packet_findings'] = len(findings_list)
    counted['references'] = len(references)
    record_count = 0
    if issued:
        # Pass 1: location, replay, coverage, cross-package groups.
        replay_cache = {}
        for record in _iter_records(packet_dir, manifest, problems):
            record_count += 1
            seq += 1
            if record.get('seq') != seq:
                problems.append(f'seq_gap:{record_count}')
                pass1_ok = False
            errs, line_text, obj = locate(record)
            if errs:
                record_problems = [f'record {record.get("seq")}:{e}' for e in errs]
                problems.extend(record_problems)
                pass1_ok = False
                continue
            errs, replay = check_replay(record, line_text)
            if errs:
                problems.extend(f'record {record.get("seq")}:{e}' for e in errs)
                pass1_ok = False
            replay_cache[record.get('seq')] = replay
            envelope = record.get('envelope') or {}
            if replay['version'] and replay['entity_id'] and obj is not None:
                groups.setdefault(replay['entity_id'], []).append(
                    (envelope.get('id'), str(obj.get('subject', '')),
                     obj.get('event_time'), obj.get('state')))
        for ref in references:
            groups.setdefault(ref['entity_id'], []).append(
                (ref['envelope_id'], ref['subject'], ref['event_time'], ref['state']))
        in_scope_entities = {key for key, members in groups.items()
                             if any(m[0] == (rec_env or {}).get('id')
                                    for rec_env in [None] for m in members)}
        # Cross-package replay from packet contents plus minimal references.
        verdict_map = {}
        cross_ok = True
        for entity_id, members in groups.items():
            try:
                for envelope_id, code in cross_verdicts(members):
                    verdict_map.setdefault(envelope_id, []).append([code, entity_id])
            except Exception as exc:
                problems.append(f'cross_replay_error:{entity_id}:{exc}')
                cross_ok = False
        check('cross_package', cross_ok, 'cross-package verdict replay failed')
        # Pass 2: full per-line classification with replayed cross verdicts.
        seq = 0
        for record in _iter_records(packet_dir, manifest, problems):
            seq += 1
            errs, line_text, obj = locate(record)
            replay = replay_cache.get(record.get('seq'))
            if errs or replay is None:
                continue
            envelope = record.get('envelope') or {}
            cross = verdict_map.get(envelope.get('id'), [])
            errs, classified = check_classification(record, line_text, replay, cross)
            if errs:
                problems.extend(f'record {record.get("seq")}:{e}' for e in errs)
                pass1_ok = False
            category = record.get('category')
            if category in CATEGORIES:
                counted[category] += 1
                counted['total_lines'] += 1
                counted['line_findings'] += len(record.get('findings') or [])
                if category in EXCEPTION_CATEGORIES:
                    counted['exceptions'] += 1
        check('line_records', pass1_ok, 'line records failed semantic replay')
    else:
        # Refusal diagnostic: verify each counterexample against its own claims.
        diag_ok = True
        for record in _iter_records(packet_dir, manifest, problems):
            record_count += 1
            errs, line_text, obj = locate(record)
            if errs:
                problems.extend(f'counterexample:{e}' for e in errs)
                diag_ok = False
                continue
            errs, replay = check_replay(record, line_text)
            cross = (record.get('replayed') or {}).get('cross_issues') or []
            more, classified = check_classification(record, line_text, replay, cross)
            errs = errs + more
            if errs:
                problems.extend(f'counterexample:{e}' for e in errs)
                diag_ok = False
            category = record.get('category')
            if category in CATEGORIES:
                counted[category] += 1
                counted['line_findings'] += len(record.get('findings') or [])
                if category in EXCEPTION_CATEGORIES:
                    counted['exceptions'] += 1
        check('counterexamples', diag_ok, 'counterexample evidence failed semantic replay')
    coverage_ok = True
    if issued:
        for sid, cov in coverage.items():
            if cov['next'] - 1 != len(cov['spans']):
                problems.append(f'line_coverage:{sid}')
                coverage_ok = False
        total = manifest.get('lines', {}).get('total') if manifest.get('lines') else None
        if total != counted['total_lines']:
            problems.append('lines_total_mismatch')
            coverage_ok = False
    check('coverage', coverage_ok, 'line records do not cover every source line exactly once')
    counts_ok = True
    if issued:
        for key in counted:
            if counted[key] != counts.get(key):
                problems.append(f'counts_mismatch:{key}')
                counts_ok = False
    else:
        if sum(counts.get(key, 0) for key in CATEGORIES) != counts.get('total_lines'):
            problems.append('counts_mismatch:total_lines')
            counts_ok = False
        total_source_lines = sum(len(spans) for spans in source_spans.values())
        if counts.get('total_lines') != total_source_lines:
            problems.append('counts_mismatch:source_lines')
            counts_ok = False
        for key in CATEGORIES:
            if counted[key] > counts.get(key, 0):
                problems.append(f'counts_mismatch:{key}')
                counts_ok = False
    if counts.get('exceptions') != (counts.get('pending', 0) + counts.get('parse_error', 0)
                                    + counts.get('version_unknown', 0)):
        problems.append('counts_mismatch:exceptions')
        counts_ok = False
    check('counts', counts_ok, 'manifest counts do not match replayed records')
    integrity = (counts.get('output_missing', 0) + counts.get('output_duplicate', 0)
                 + counts.get('tampered', 0) + counts.get('line_findings', 0)
                 + counts.get('packet_findings', 0))
    exceptions = counts.get('exceptions', 0)
    conformance_ok = True
    if status == ISSUED:
        conformance_ok = integrity == 0 and exceptions == 0 and not findings_list
    elif status == ISSUED_WITH_EXCEPTIONS:
        conformance_ok = (policy == 'exceptions_attested' and integrity == 0
                          and exceptions > 0 and not findings_list)
    elif status == REFUSED:
        if policy == 'exceptions_attested':
            justified = integrity > 0
        else:
            justified = integrity > 0 or exceptions > 0
        conformance_ok = justified and (record_count > 0 or bool(findings_list))
    else:
        conformance_ok = False
    check('policy_conformance', conformance_ok,
          'packet status does not satisfy its frozen policy')
    result['ok'] = not problems
    return result
