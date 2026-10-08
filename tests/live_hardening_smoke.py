import base64,json,secrets,time,subprocess
import os
from uuid import uuid4
import docker,requests
from bs4 import BeautifulSoup
from flask import Flask
from pathlib import Path

if os.environ.get('RUN_LIVE_HARDENING_TESTS') != '1':
    raise SystemExit('Set RUN_LIVE_HARDENING_TESTS=1 to explicitly test the local deployed stack and restart its frontend.')

client=docker.from_env()
worker=client.containers.get('url-sandbox-workers_api-1')
site=client.containers.get('url-sandbox-website-1')
name='codex-hardening-'+uuid4().hex[:12]
session=requests.Session(); session.trust_env=False
task=None; paused=False

def check(label): print(json.dumps({'check':label,'result':'PASS'}),flush=True)
def http(method,path,expected=200,**kwargs):
    response=session.request(method,'http://127.0.0.1:8000'+path,timeout=20,**kwargs)
    assert response.status_code==expected,(path,response.status_code)
    return response
def csrf(response):return BeautifulSoup(response.content,'html.parser').find('input',{'name':'csrf_token'})['value']
def guest(code):
    result=worker.exec_run(['python','-c',code])
    assert result.exit_code==0,result.output.decode()[-500:]
    return result.output.decode().strip()

try:
    for container,port in [('url-sandbox_redis','6379/tcp'),('url-sandbox-mongodb-1','27017/tcp')]:
        bindings=client.containers.get(container).attrs['HostConfig']['PortBindings'][port]
        assert all(binding['HostIp']=='127.0.0.1' for binding in bindings)
    check('database_ports_loopback_only')
    common="from os import environ;from shared.settings import json_settings;from redis import Redis;s=json_settings[environ['project_env']];r=Redis.from_url(s['redis_settings']);"
    config=json.loads(guest(common+"import json;print(json.dumps(r.config_get('appendonly','appendfsync')))"))
    assert config=={'appendonly':'yes','appendfsync':'everysec'}
    check('persistent_redis_aof_enabled')
    form=http('GET','/register/')
    http('POST','/register/',expected=302,allow_redirects=False,
         data={'login':name,'password':secrets.token_urlsafe(24),'csrf_token':csrf(form)})
    form=http('GET','/apikeys/')
    created=http('POST','/apikeys/',data={'action':'create','label':'Temporary hardening proof','csrf_token':csrf(form)})
    token=next(node.text for node in BeautifulSoup(created.content,'html.parser').find_all('code')
               if node.text.startswith('usp_') and len(node.text)>40)
    for value in [-1,121,10**9,True]:
        http('POST','/api/v1/analyze',expected=400,json={'url':'https://example.com','analyzer_timeout':value})
    check('actual_api_timeout_validation')
    active=json.loads(guest(common+"import json;from celery import Celery;a=Celery(s['celery_settings']['name'],broker=s['celery_settings']['celery_broker_url']);i=a.control.inspect(timeout=3);x=i.active();y=i.reserved();print(json.dumps({'workers':len(x or {}),'active':sum(map(len,(x or {}).values())),'reserved':sum(map(len,(y or {}).values())),'queued':r.llen(s['worker']['queue'])}))"))
    assert active=={'workers':1,'active':0,'reserved':0,'queued':0},'Worker not idle; safe pause skipped'
    worker.pause(); paused=True
    task=http('POST','/api/v1/analyze',expected=201,json={'url':'https://example.com','use_proxy':False}).json()['task_id']
    Path('/tmp/url-sandbox-hardening-owned.json').write_text(json.dumps({'login':name,'task':task}))
    Path('/tmp/url-sandbox-hardening-owned.json').chmod(0o600)
    assert http('GET','/api/v1/tasks/'+task).json()['status']=='queued'
    site.restart(timeout=10)
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        try:
            response=session.get('http://127.0.0.1:8000/api/v1/tasks/'+task,timeout=3)
            if response.status_code==200:break
        except requests.RequestException:pass
        time.sleep(1)
    else:raise RuntimeError('Website did not recover')
    assert response.json()['status']=='queued'
    anonymous=requests.Session();anonymous.trust_env=False
    assert anonymous.get('http://127.0.0.1:8000/api/v1/tasks/'+task,
                         headers={'X-API-Key':token},timeout=10).status_code==200
    check('queued_task_cookie_and_api_key_survive_frontend_restart')
    # Remove only the paused test message, never purge the queue or run the task.
    remove=common+"import json;n=0;q=s['worker']['queue']\nfor payload in r.lrange(q,0,-1):\n if json.loads(payload).get('headers',{}).get('id')=="+repr(task)+":n+=r.lrem(q,1,payload)\nprint(n)"
    # A paused container cannot exec; remove via the sibling maintenance container first.
    maintenance=client.containers.get('url-sandbox-maintenance-1')
    output=maintenance.exec_run(['python','-c',remove])
    assert output.exit_code==0 and output.output.strip() in (b'0',b'1')
    # Redis may have delivered BRPOP data to the paused worker's socket already.
    cancel="from datetime import datetime;from shared.mongodbconn import CLIENT;from shared.settings import defaultdb;CLIENT[defaultdb['dbname']].taskdblogs.update_one({'task':"+repr(task)+"},{'$set':{'status':'cancelled','end':datetime.utcnow()}})"
    assert maintenance.exec_run(['python','-c',cancel]).exit_code==0
    worker.unpause();paused=False
    time.sleep(2)
    uid=guest("from shared.mongodbconn import CLIENT;from shared.settings import defaultdb;print(str(CLIENT[defaultdb['dbname']].users.find_one({'login':"+repr(name)+"})['_id']))")
    original={};exec(subprocess.check_output(['git','show','c138b775fd3857a0093e44f5927317eeff572fea:shared/settings.py'],text=True),original)
    legacy=Flask('legacy_cookie');legacy.secret_key=original['json_settings']['docker']['backend_key']
    forged=legacy.session_interface.get_signing_serializer(legacy).dumps({'_user_id':uid,'_fresh':True})
    attacker=requests.Session();attacker.trust_env=False;attacker.cookies.set('session',forged,domain='127.0.0.1',path='/')
    assert attacker.get('http://127.0.0.1:8000/api/v1/tasks/'+task,timeout=10).status_code==401
    check('public_legacy_secret_cookie_rejected_on_real_stack')
    print(json.dumps({'result':'PASS'}),flush=True)
finally:
    if paused:
        # Delete the owned message using maintenance before releasing the worker.
        if task:
            maintenance=client.containers.get('url-sandbox-maintenance-1')
            maintenance.exec_run(['python','-c',common+"import json;q=s['worker']['queue']\nfor payload in r.lrange(q,0,-1):\n if json.loads(payload).get('headers',{}).get('id')=="+repr(task)+":r.lrem(q,1,payload)"])
            maintenance.exec_run(['python','-c',"from datetime import datetime;from shared.mongodbconn import CLIENT;from shared.settings import defaultdb;CLIENT[defaultdb['dbname']].taskdblogs.update_one({'task':"+repr(task)+"},{'$set':{'status':'cancelled','end':datetime.utcnow()}})"])
        worker.unpause()
        time.sleep(2)
    cleanup="from shared.mongodbconn import CLIENT;from shared.settings import defaultdb;from bson import ObjectId;db=CLIENT[defaultdb['dbname']];u=db.users.find_one({'login':"+repr(name)+"});owner=str(u['_id']) if u else '';ids=[row['task'] for row in db.taskdblogs.find({'owner_id':owner})]\nfor task_id in ids:\n db.taskdblogs.delete_many({'task':task_id})\n db.task_log_lines.delete_many({'task':task_id})\ndb.api_keys.delete_many({'owner_id':owner});db.users.delete_many({'login':"+repr(name)+"});print('Temporary hardening account and queued task removed')"
    print(guest(cleanup),flush=True)
