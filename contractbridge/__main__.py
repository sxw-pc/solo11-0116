import argparse,json,tempfile
from pathlib import Path
from . import engine
def demo():
    root=Path(tempfile.mkdtemp(prefix='contractbridge-'));db=root/'ledger.db'
    contract={'versions':[{'version':'v1','signature':['/legacy']},{'version':'v2','signature':['/new']}],'required':['id','amount'], 'rules':[{'target':'id','source':'/entity_id'},{'target':'amount','source':'/legacy/value','op':'scale','factor':100}], 'errors':{'TEMP':'retry','FATAL':'failed'}}
    h=engine.freeze(db,contract);p=root/'input.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A-1','subject':'Example','legacy':{'value':2},'status':'ok'}));engine.ingest(db,p,contract);engine.translate(db,h);print(engine.report(db,h,root/'report.json'))
def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True);sub.add_parser('demo')
    s=sub.add_parser('freeze');s.add_argument('--db',required=True);s.add_argument('contract')
    s=sub.add_parser('ingest');s.add_argument('--db',required=True);s.add_argument('contract');s.add_argument('source')
    for n in ('normalize','errors'):
        s=sub.add_parser(n);s.add_argument('contract');s.add_argument('envelope')
    for n in ('translate','reconcile','verify','report'):
        s=sub.add_parser(n);s.add_argument('--db',required=True);s.add_argument('--contract-hash',required=True)
        if n=='report':s.add_argument('--out',required=True)
    x=p.parse_args()
    if x.cmd=='demo':demo()
    elif x.cmd=='freeze':print(engine.freeze(x.db,json.loads(Path(x.contract).read_text())))
    elif x.cmd=='ingest':print(engine.ingest(x.db,x.source,json.loads(Path(x.contract).read_text())))
    elif x.cmd in ('normalize','errors'):
        c=json.loads(Path(x.contract).read_text());obj=json.loads(Path(x.envelope).read_text());out,evidence,issues=engine.transform(obj,c)
        print(json.dumps({'entity_id':obj.get('entity_id'),'subject':obj.get('subject'),'status':out.get('status'),'evidence':evidence,'issues':issues},ensure_ascii=False))
    elif x.cmd=='translate':print(engine.translate(x.db,x.contract_hash))
    elif x.cmd=='reconcile':print(engine.reconcile(x.db))
    elif x.cmd=='verify':print(engine.verify(x.db,x.contract_hash))
    else:print(engine.report(x.db,x.contract_hash,x.out))
if __name__=='__main__':main()
