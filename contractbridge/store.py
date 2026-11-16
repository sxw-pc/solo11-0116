import sqlite3
from pathlib import Path
SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS contract(id INTEGER PRIMARY KEY,version TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source(id INTEGER PRIMARY KEY,hash TEXT NOT NULL UNIQUE,body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS envelope(id INTEGER PRIMARY KEY,source_id INT REFERENCES source(id),line_no INT,version TEXT,status TEXT,raw TEXT,entity_id TEXT,UNIQUE(source_id,line_no));
CREATE TABLE IF NOT EXISTS entity(id TEXT PRIMARY KEY,subject TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run(id INTEGER PRIMARY KEY,source_id INT REFERENCES source(id),contract_id INT REFERENCES contract(id),status TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(source_id,contract_id));
CREATE TABLE IF NOT EXISTS output(id INTEGER PRIMARY KEY,run_id INT REFERENCES run(id),envelope_id INT REFERENCES envelope(id),body TEXT NOT NULL,hash TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(output_id INT REFERENCES output(id),field TEXT NOT NULL,pointer TEXT,rule TEXT NOT NULL,PRIMARY KEY(output_id,field));
CREATE TABLE IF NOT EXISTS issue(id INTEGER PRIMARY KEY,envelope_id INT REFERENCES envelope(id),run_id INT REFERENCES run(id),code TEXT NOT NULL,detail TEXT NOT NULL);
"""
def connect(path):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(p);db.row_factory=sqlite3.Row;db.executescript(SCHEMA);return db
