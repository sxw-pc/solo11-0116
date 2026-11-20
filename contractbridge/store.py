import sqlite3
from pathlib import Path
SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS contract(id INTEGER PRIMARY KEY,version TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,body TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS contract_version_unique ON contract(version);
CREATE TABLE IF NOT EXISTS source(id INTEGER PRIMARY KEY,hash TEXT NOT NULL UNIQUE,body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS envelope(id INTEGER PRIMARY KEY,source_id INT REFERENCES source(id),line_no INT,version TEXT,status TEXT,raw TEXT,entity_id TEXT,UNIQUE(source_id,line_no));
CREATE TABLE IF NOT EXISTS entity(id TEXT PRIMARY KEY,subject TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run(id INTEGER PRIMARY KEY,source_id INT REFERENCES source(id),contract_id INT REFERENCES contract(id),status TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(source_id,contract_id));
CREATE TABLE IF NOT EXISTS output(id INTEGER PRIMARY KEY,run_id INT REFERENCES run(id),envelope_id INT REFERENCES envelope(id),body TEXT NOT NULL,hash TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(output_id INT REFERENCES output(id),field TEXT NOT NULL,pointer TEXT,rule TEXT NOT NULL,PRIMARY KEY(output_id,field));
CREATE TABLE IF NOT EXISTS issue(id INTEGER PRIMARY KEY,envelope_id INT REFERENCES envelope(id),run_id INT REFERENCES run(id),code TEXT NOT NULL,detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS consumer_policy(id INTEGER PRIMARY KEY,consumer TEXT NOT NULL UNIQUE,contract_hash TEXT NOT NULL,amount_limit INTEGER NOT NULL CHECK(amount_limit>=0));
CREATE TABLE IF NOT EXISTS allocation(id INTEGER PRIMARY KEY,consumer TEXT NOT NULL,contract_hash TEXT NOT NULL,output_id INT NOT NULL REFERENCES output(id),status TEXT NOT NULL,reason TEXT NOT NULL,UNIQUE(consumer,output_id));
CREATE TABLE IF NOT EXISTS delivery(id INTEGER PRIMARY KEY,consumer TEXT NOT NULL,contract_hash TEXT NOT NULL,status TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(consumer,contract_hash));
CREATE TABLE IF NOT EXISTS delivery_item(delivery_id INT REFERENCES delivery(id),output_id INT REFERENCES output(id),hash TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(delivery_id,output_id));
CREATE TABLE IF NOT EXISTS delivery_ack(id INTEGER PRIMARY KEY,delivery_id INT REFERENCES delivery(id),output_id INT REFERENCES output(id),hash TEXT NOT NULL,result TEXT NOT NULL,UNIQUE(delivery_id,output_id));
CREATE TABLE IF NOT EXISTS migration_plan(id TEXT PRIMARY KEY,baseline_hash TEXT NOT NULL REFERENCES contract(hash),target_hash TEXT NOT NULL REFERENCES contract(hash),max_amount_delta REAL NOT NULL,status TEXT NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS migration_diff(plan_id TEXT NOT NULL REFERENCES migration_plan(id),envelope_id INT NOT NULL REFERENCES envelope(id),baseline_output INT REFERENCES output(id),target_output INT REFERENCES output(id),amount_delta REAL,status TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(plan_id,envelope_id));
"""
def connect(path):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(p);db.row_factory=sqlite3.Row;db.executescript(SCHEMA);return db
def snapshot(path):
    """Open one consistent read snapshot: every read shares a single transaction.

    Audit issuance reads the whole request scope from one database state.
    TEMP tables stay available as bounded-memory replay scratch space."""
    p=Path(path);db=sqlite3.connect(p,isolation_level=None);db.row_factory=sqlite3.Row
    db.execute('BEGIN');return db
