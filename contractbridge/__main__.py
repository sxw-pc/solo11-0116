import argparse,json,tempfile
from pathlib import Path
from . import engine,operations,migration,transactions
def transaction_contract(protocol):
    rules=[{'target':'id','source':'/entity_id'},
           {'target':'txn_id','source':'/txn'},
           {'target':'event','source':'/kind','op':'enum','values':{'order':'order','auth':'authorize','capture':'capture','refund':'refund','void':'void'}},
           {'target':'event_time','source':'/biz_time'},
           {'target':'amount','source':'/amount'},
           {'target':'event_key','source':'/event_key'},
           {'target':'credential','source':'/credential','nullable':True}]
    tx={'protocol':protocol,'transaction_id_field':'txn_id','event_field':'event',
        'time_field':'event_time','amount_field':'amount','event_id_field':'event_key',
        'credential_field':'credential','required_events':['order','capture']}
    return {'versions':[{'version':protocol[:2]+'1','signature':['/biz_time']},{'version':protocol[:2]+'2','signature':['/new_event']}],
            'required':['id','txn_id','event','event_time','amount','event_key'],
            'rules':rules,'errors':{'TEMP':'retry','FATAL':'failed'},'transaction':tx}
def txn_envelope(version,entity,kind,amount,key,time,credential=None,txn='T-100'):
    obj={'version':version,'entity_id':entity,'subject':'Payment platform','txn':txn,
         'kind':kind,'biz_time':time,'amount':amount,'event_key':key,'status':'ok',
         'baseline_marker':'db-cohort'}
    if credential:obj['credential']=credential
    return json.dumps(obj,ensure_ascii=False)
def demo():
    root=Path(tempfile.mkdtemp(prefix='contractbridge-'));db=root/'ledger.db'
    contract={'versions':[{'version':'v1','signature':['/legacy']},{'version':'v2','signature':['/new']}],'required':['id','amount'], 'rules':[{'target':'id','source':'/entity_id'},{'target':'amount','source':'/legacy/value','op':'scale','factor':100}], 'errors':{'TEMP':'retry','FATAL':'failed'}}
    h=engine.freeze(db,contract);p=root/'input.jsonl';p.write_text(json.dumps({'version':'v1','entity_id':'A-1','subject':'Example','legacy':{'value':2},'status':'ok'}));engine.ingest(db,p,contract);engine.translate(db,h);operations.policy(db,'demo-consumer',h,500);print(operations.allocate(db,'demo-consumer'));delivery=operations.dispatch(db,'demo-consumer');print(operations.acknowledge(db,delivery['id'],delivery['items'][0]['output_id'],delivery['items'][0]['hash'],'接收'));print(engine.report(db,h,root/'report.json'))
    target=json.loads(json.dumps(contract));target['versions'][-1]['version']='v3';target['rules'][1]['factor']=110
    target_hash=engine.freeze(db,target);engine.translate(db,target_hash)
    migration.plan(db,'demo-cutover',h,target_hash,10)
    print(migration.compare(db,'demo-cutover'))
    tdb=root/'transactions.db'
    preauth=transaction_contract('preauth');preauth_hash=engine.freeze(tdb,preauth)
    direct=transaction_contract('direct_debit');direct_hash=engine.freeze(tdb,direct)
    # The baseline freezes parallel db1/db2 labels under its own body.
    # Synthetic envelopes declare both versions, so both contracts identify the
    # same envelope rows and the cohort comparison is truly envelope-by-envelope.
    base_direct=json.loads(json.dumps(direct))
    base_direct['versions']=[{'version':'db1','signature':['/baseline_marker']},
                             {'version':'db2','signature':['/new_event']}]
    base_direct_hash=engine.freeze(tdb,base_direct)
    # Each synthetic interface package is ingested only by the contracts whose
    # versions it speaks; the same business story is re-expressed per protocol.
    # T-300 is the healthy control: a fully authorized preauth chain and a
    # direct-debit chain whose credential is used exactly once.
    pa_t300=[txn_envelope('pa1','ORD-3','order',80,'evt-order-3','2026-03-01T10:00:00Z',txn='T-300'),
             txn_envelope('pa1','AUTH-3','auth',80,'evt-auth-3','2026-03-01T10:01:00Z',txn='T-300'),
             txn_envelope('pa1','PAY-3','capture',80,'evt-cap-3','2026-03-01T10:02:00Z','pa-cred-3',txn='T-300')]
    dd_t300=[txn_envelope('dd1','ORD-3','order',80,'evt-order-3','2026-03-01T10:00:00Z',txn='T-300'),
             txn_envelope('dd1','PAY-3','capture',80,'evt-cap-3','2026-03-01T10:02:00Z','dc-cred-3',txn='T-300')]
    pa_t100=[txn_envelope('pa1','ORD-1','order',100,'evt-order-1','2026-02-01T10:00:00Z'),
             txn_envelope('pa1','PAY-1','capture',100,'evt-cap-1','2026-02-01T10:05:00Z','pa-cred-1')]
    dd_t100=[line.replace('"pa1"','"dd1"').replace('pa-cred-1','dc-cred-1') for line in pa_t100]
    pa_t200=[txn_envelope('pa1','ORD-2','order',50,'evt-order-2','2026-02-02T09:00:00Z',txn='T-200'),
             txn_envelope('pa1','PAY-2','capture',50,'evt-cap-2','2026-02-02T09:05:00Z','pa-cred-2',txn='T-200')]
    # Direct-debit T-200 reuses the T-100 credential, which must not be reusable.
    dd_t200=[line.replace('"pa1"','"dd1"').replace('pa-cred-2','dc-cred-1') for line in pa_t200]
    # The refund response sits at the end of the package although its business
    # instant is the latest one — ingestion order and reconstruction order are
    # deliberately different; the snapshot below records the pre-refund verdict.
    dd_refund=txn_envelope('dd1','REF-1','refund',30,'evt-ref-1','2026-02-03T08:00:00Z')
    pa_source=root/'preauth.jsonl';pa_source.write_text('\n'.join(pa_t300+pa_t100+pa_t200))
    main_lines=dd_t300+dd_t100+dd_t200
    dd_source=root/'direct.jsonl';dd_source.write_text('\n'.join(main_lines))
    # The late package carries only the new refund envelope; reconstruction
    # re-reads every previously translated event and appends this one.
    late_source=root/'direct-late.jsonl';late_source.write_text(dd_refund)
    # One package feeds both direct-debit contracts; each translate keeps only
    # the envelopes whose signatures it froze.
    engine.ingest(tdb,pa_source,preauth)
    engine.ingest(tdb,dd_source,direct);engine.ingest(tdb,dd_source,base_direct)
    engine.translate(tdb,preauth_hash);engine.translate(tdb,direct_hash);engine.translate(tdb,base_direct_hash)
    print('preauth verdict (order100/capture100 without authorization):',
          json.dumps(transactions.reconcile_transactions(tdb,preauth_hash),ensure_ascii=False))
    before_refund={r['transaction_id']:r['balances']['refundable']
                   for r in transactions.reconcile_transactions(tdb,direct_hash)}
    print('direct-debit verdict (same inputs; T-200 reuses credential), refundable before refund:',
          json.dumps(before_refund,ensure_ascii=False))
    # The late refund package adds envelope rows shared by both cohorts;
    # re-translation rebuilds the chain and preserves every prior event.
    engine.ingest(tdb,late_source,direct);engine.ingest(tdb,late_source,base_direct)
    engine.translate(tdb,direct_hash);engine.translate(tdb,base_direct_hash)
    print('direct-debit after late refund 30 (refundable 100 -> 70, history retained):',
          json.dumps(transactions.reconcile_transactions(tdb,direct_hash),ensure_ascii=False))
    print(engine.report(tdb,direct_hash,root/'txn-report.json'))
    migration.plan(tdb,'txn-cutover',base_direct_hash,direct_hash,0)
    print('transaction cohort compare (per-envelope equal, transaction pending):',
          json.dumps(migration.compare(tdb,'txn-cutover'),ensure_ascii=False))
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
    s=sub.add_parser('transactions');s.add_argument('--db',required=True);s.add_argument('--contract-hash',required=True)
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
    elif x.cmd=='transactions':print(json.dumps(transactions.reconcile_transactions(x.db,x.contract_hash),ensure_ascii=False,indent=2))
    else:print(engine.report(x.db,x.contract_hash,x.out))
if __name__=='__main__':main()
