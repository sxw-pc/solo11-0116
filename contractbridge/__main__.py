import argparse,json,tempfile
from pathlib import Path
from . import engine,operations,migration
def demo():
    root=Path(tempfile.mkdtemp(prefix='contractbridge-'));db=root/'ledger.db'
    contract={'versions':[{'version':'v1','signature':['/legacy']},{'version':'v2','signature':['/new']}],'required':['id','amount'], 'rules':[{'target':'id','source':'/entity_id'},{'target':'amount','source':'/legacy/value','op':'scale','factor':100}], 'errors':{'TEMP':'retry','FATAL':'failed'}}
    h=engine.freeze(db,contract);p=root/'input.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A-1','subject':'Example','legacy':{'value':2},'status':'ok'}));engine.ingest(db,p,contract);engine.translate(db,h);operations.policy(db,'demo-consumer',h,500);print(operations.allocate(db,'demo-consumer'));delivery=operations.dispatch(db,'demo-consumer');print(operations.acknowledge(db,delivery['id'],delivery['items'][0]['output_id'],delivery['items'][0]['hash'],'接收'));print(engine.report(db,h,root/'report.json'))
    target=json.loads(json.dumps(contract));target['versions'][-1]['version']='v3';target['rules'][1]['factor']=110
    target_hash=engine.freeze(db,target);engine.translate(db,target_hash)
    migration.plan(db,'demo-cutover',h,target_hash,10)
    print(migration.compare(db,'demo-cutover'))
def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True);sub.add_parser('demo')
    s=sub.add_parser('freeze');s.add_argument('--db',required=True);s.add_argument('contract')
    s=sub.add_parser('ingest');s.add_argument('--db',required=True);s.add_argument('contract');s.add_argument('source')
    for n in ('normalize','errors'):
        s=sub.add_parser(n);s.add_argument('contract');s.add_argument('envelope')
    for n in ('translate','reconcile','verify','report'):
        s=sub.add_parser(n);s.add_argument('--db',required=True);s.add_argument('--contract-hash',required=True)
        if n=='report':s.add_argument('--out',required=True)
    s=sub.add_parser('consumer-policy');s.add_argument('--db',required=True);s.add_argument('--consumer',required=True);s.add_argument('--contract-hash',required=True);s.add_argument('--limit',required=True,type=int)
    for n in ('allocate','dispatch'):
        s=sub.add_parser(n);s.add_argument('--db',required=True);s.add_argument('--consumer',required=True)
    s=sub.add_parser('acknowledge');s.add_argument('--db',required=True);s.add_argument('--delivery-id',required=True,type=int);s.add_argument('--output-id',required=True,type=int);s.add_argument('--hash',required=True);s.add_argument('--result',required=True,choices=['接收','失败'])
    s=sub.add_parser('delivery-status');s.add_argument('--db',required=True);s.add_argument('--delivery-id',required=True,type=int)
    s=sub.add_parser('migration-plan');s.add_argument('--db',required=True);s.add_argument('--id',required=True);s.add_argument('--baseline-hash',required=True);s.add_argument('--target-hash',required=True);s.add_argument('--max-amount-delta',required=True,type=float)
    s=sub.add_parser('migration-compare');s.add_argument('--db',required=True);s.add_argument('--id',required=True)
    s=sub.add_parser('repair-open');s.add_argument('--db',required=True);s.add_argument('case')
    s=sub.add_parser('repair-describe');s.add_argument('--db',required=True);s.add_argument('--id',required=True)
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
    elif x.cmd=='consumer-policy':print(operations.policy(x.db,x.consumer,x.contract_hash,x.limit))
    elif x.cmd=='allocate':print(operations.allocate(x.db,x.consumer))
    elif x.cmd=='dispatch':print(operations.dispatch(x.db,x.consumer))
    elif x.cmd=='acknowledge':print(operations.acknowledge(x.db,x.delivery_id,x.output_id,x.hash,x.result))
    elif x.cmd=='delivery-status':print(operations.delivery_status(x.db,x.delivery_id))
    elif x.cmd=='migration-plan':migration.plan(x.db,x.id,x.baseline_hash,x.target_hash,x.max_amount_delta)
    elif x.cmd=='migration-compare':print(migration.compare(x.db,x.id))
    elif x.cmd=='repair-open':
        from .repair import open_case
        print(open_case(x.db,json.loads(Path(x.case).read_text(encoding='utf-8'))))
    elif x.cmd=='repair-describe':
        from .repair import describe
        print(describe(x.db,x.id))
    else:print(engine.report(x.db,x.contract_hash,x.out))
if __name__=='__main__':main()
