from pathlib import Path
import hashlib
import json
import pytest
from contractbridge.feed import declare,describe


def test_frozen_supplier_declaration(tmp_path):
    fixture=Path(__file__).resolve().parents[1]/'fixtures'/'supplier-feed-declaration.json'
    item=json.loads(fixture.read_bytes())
    payload=fixture.with_name(item['file_name']).read_bytes()
    assert item['byte_count']==len(payload)
    assert item['envelope_count']==len(payload.splitlines())
    assert item['content_sha']==hashlib.sha256(payload).hexdigest()
    db=tmp_path/'control.db'
    first=declare(db,fixture)
    assert declare(db,fixture)==first
    assert describe(db,'feed-1')['supplier']=='supplier-A'
    altered=tmp_path/'other.json';altered.write_text(fixture.read_text().replace('supplier-A','supplier-B'),encoding='utf-8')
    with pytest.raises(ValueError,match='feed_identity_conflict'):
        declare(db,altered)
