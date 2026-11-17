"""Freeze a local migration canary frame and its declared review sample."""
import hashlib
import json
from pathlib import Path

from .store import connect

SCHEMA="""
CREATE TABLE IF NOT EXISTS migration_canary(
 id TEXT PRIMARY KEY,plan_id TEXT NOT NULL REFERENCES migration_plan(id),
 frame_hash TEXT NOT NULL,design_json TEXT NOT NULL);
"""

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def register(db_path,canary_id,plan_id,design):
    if not canary_id or not isinstance(design,dict) or not isinstance(design.get('strata'),list) or not design['strata']:
        raise ValueError('invalid_canary_design')
    db=connect(db_path)
    try:
        db.executescript(SCHEMA)
        plan=db.execute('SELECT * FROM migration_plan WHERE id=?',(plan_id,)).fetchone()
        if not plan:
            raise ValueError('unknown_migration_plan')
        all_ids=set()
        labels=set()
        for stratum in design['strata']:
            label=stratum.get('label')
            frame=stratum.get('frame_ids')
            selected=stratum.get('selected_ids')
            if not label or label in labels or not isinstance(frame,list) or not frame or not isinstance(selected,list) or not selected:
                raise ValueError('invalid_canary_stratum')
            if len(frame)!=len(set(frame)) or len(selected)!=len(set(selected)) or not set(selected)<=set(frame) or all_ids & set(frame):
                raise ValueError('invalid_canary_selection')
            labels.add(label);all_ids.update(frame)
        known={row['id'] for row in db.execute('SELECT id FROM envelope')}
        if not all_ids<=known:
            raise ValueError('unknown_canary_envelope')
        frozen={'plan_id':plan_id,'baseline_hash':plan['baseline_hash'],
                'target_hash':plan['target_hash'],'strata':design['strata']}
        body=_canonical(frozen)
        digest=hashlib.sha256(body.encode('utf-8')).hexdigest()
        old=db.execute('SELECT * FROM migration_canary WHERE id=?',(canary_id,)).fetchone()
        if old:
            if old['plan_id']!=plan_id or old['frame_hash']!=digest or old['design_json']!=body:
                raise ValueError('canary_identity_conflict')
            return inspect(db_path,canary_id)
        with db:
            db.execute('INSERT INTO migration_canary VALUES (?,?,?,?)',(canary_id,plan_id,digest,body))
        return inspect(db_path,canary_id)
    finally:
        db.close()

def inspect(db_path,canary_id):
    db=connect(db_path)
    try:
        db.executescript(SCHEMA)
        row=db.execute('SELECT * FROM migration_canary WHERE id=?',(canary_id,)).fetchone()
        if not row:
            raise ValueError('unknown_canary')
        return {**dict(row),'design':json.loads(row['design_json'])}
    finally:
        db.close()

def load_fixture(db_path,fixture_path):
    data=json.loads(Path(fixture_path).read_text(encoding='utf-8'))
    return register(db_path,data['id'],data['plan_id'],data['design'])
