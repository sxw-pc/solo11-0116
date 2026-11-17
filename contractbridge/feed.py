"""Freeze a supplier's declared local JSONL handoff before ingestion."""
import hashlib
import json
from pathlib import PurePosixPath,Path
from .store import connect

SCHEMA="""
CREATE TABLE IF NOT EXISTS feed_declaration(
 id TEXT PRIMARY KEY, supplier TEXT NOT NULL, file_name TEXT NOT NULL,
 byte_count INTEGER NOT NULL, envelope_count INTEGER NOT NULL,
 content_sha TEXT NOT NULL, declaration_sha TEXT NOT NULL, raw BLOB NOT NULL);
"""

def declare(db_path,declaration_path):
    raw=Path(declaration_path).read_bytes();item=json.loads(raw)
    name=item.get('file_name','');p=PurePosixPath(name)
    if not item.get('id') or not item.get('supplier') or not name or p.is_absolute() or '..' in p.parts or '\\' in name:
        raise ValueError('invalid_feed_identity')
    if not isinstance(item.get('byte_count'),int) or item['byte_count']<0 or not isinstance(item.get('envelope_count'),int) or item['envelope_count']<0:
        raise ValueError('invalid_feed_size')
    content_sha=item.get('content_sha','')
    if len(content_sha)!=64 or any(c not in '0123456789abcdef' for c in content_sha):
        raise ValueError('invalid_feed_digest')
    digest=hashlib.sha256(raw).hexdigest();db=connect(db_path)
    try:
        db.executescript(SCHEMA)
        with db:
            old=db.execute('SELECT declaration_sha FROM feed_declaration WHERE id=?',(item['id'],)).fetchone()
            if old and old['declaration_sha']!=digest:raise ValueError('feed_identity_conflict')
            db.execute('INSERT OR IGNORE INTO feed_declaration VALUES (?,?,?,?,?,?,?,?)',
                       (item['id'],item['supplier'],name,item['byte_count'],item['envelope_count'],content_sha,digest,raw))
        return {'id':item['id'],'declaration_sha':digest}
    finally:db.close()

def describe(db_path,feed_id):
    db=connect(db_path)
    try:
        db.executescript(SCHEMA)
        row=db.execute('SELECT id,supplier,file_name,byte_count,envelope_count,content_sha,declaration_sha FROM feed_declaration WHERE id=?',(feed_id,)).fetchone()
        if not row:raise ValueError('unknown_feed')
        return dict(row)
    finally:db.close()
