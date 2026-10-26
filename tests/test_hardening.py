from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import ast

import pytest
from shared.security import load_session_secret, validate_timeouts, login_attempt
from shared.lifecycle import task_status
from conftest import logged_in


def test_secret_is_required_persistent_and_not_public(tmp_path, monkeypatch):
    monkeypatch.delenv('URL_SANDBOX_SESSION_SECRET', raising=False)
    key = tmp_path / 'key'
    monkeypatch.setenv('URL_SANDBOX_SESSION_SECRET_FILE', str(key))
    with pytest.raises(RuntimeError): load_session_secret()
    key.write_text('x' * 64)
    assert load_session_secret() == load_session_secret() == 'x' * 64
    key.write_text('short')
    with pytest.raises(RuntimeError): load_session_secret()


def test_unreadable_secret_names_file_and_reason(tmp_path, monkeypatch):
    monkeypatch.delenv('URL_SANDBOX_SESSION_SECRET', raising=False)
    key = tmp_path / 'key'
    key.mkdir()  # what Docker leaves behind when the bind-mounted file is missing
    monkeypatch.setenv('URL_SANDBOX_SESSION_SECRET_FILE', str(key))
    with pytest.raises(RuntimeError, match='Is a directory') as error:
        load_session_secret()
    assert str(key) in str(error.value)


def test_init_script_replaces_docker_created_directory(tmp_path):
    import shutil, subprocess, sys
    root = tmp_path / 'repo'
    (root / 'scripts').mkdir(parents=True)
    shutil.copy(Path(__file__).resolve().parents[1] / 'scripts/init_session_secret.py', root / 'scripts')
    (root / '.secrets/flask-session.key').mkdir(parents=True)
    out = subprocess.run([sys.executable, str(root / 'scripts/init_session_secret.py')],
                         capture_output=True, text=True, check=True).stdout
    key = root / '.secrets/flask-session.key'
    assert key.is_file() and len(key.read_text().strip()) >= 48
    assert 'Private session secret created' in out


@pytest.mark.parametrize('value', [-1, 0, 121, 10**9, True, 1.5, None, {}, 'invalid'])
def test_invalid_timeouts_never_dispatch(env, value):
    web, _, alice, _, dispatched = env
    response = logged_in(web, alice).post('/api/v1/analyze', json={
        'url': 'https://example.com', 'analyzer_timeout': value})
    assert response.status_code == 400 and not dispatched


def test_ui_options_are_validated_before_enqueue(env):
    web, _, alice, _, dispatched = env
    response = logged_in(web, alice).post('/url/', data={
        'buffer':'https://example.com', 'useragents':'Chrome', 'urltimeout':'999999',
        'analyzertimeout':'60','interactivetimeout':'300'})
    assert response.status_code == 400 and not dispatched


def test_login_limit_shared_by_clients_and_not_spoofed_by_forwarded_headers(env):
    web, db, alice, _, _ = env
    alice.password = web.BCRYPT.generate_password_hash('correct', rounds=4).decode()
    alice.save()
    for index in range(10):
        response = web.APP.test_client().post('/login/', data={'login':'alice','password':'wrong'},
            headers={'X-Forwarded-For':f'198.51.100.{index}'})
        assert response.status_code == 200
    limited = web.APP.test_client().post('/login/', data={'login':'alice','password':'wrong'})
    assert limited.status_code == 429 and int(limited.headers['Retry-After']) > 0
    assert db.login_attempts.count_documents({}) == 2


def test_login_window_expires_without_waiting_for_ttl(env):
    _, db, *_ = env
    base = int(__import__('time').time() // 900) * 900 + 900
    for _ in range(10): assert login_attempt(db.login_attempts, 'user','ip',now=base+100)[0]
    assert not login_attempt(db.login_attempts,'user','ip',now=base+100)[0]
    assert login_attempt(db.login_attempts,'user','ip',now=base+901)[0]


def test_started_jobs_cannot_be_replayed_and_queued_jobs_survive(env):
    from shared.logger import setup_task_logger, cancel_task_logger
    web, db, alice, _, _ = env
    task = str(uuid4())
    parsed={'task':task,'owner_id':str(alice.id)}
    db.taskdblogs.insert_one(dict(parsed,status='queued',start=datetime.utcnow(),end=None,logs=[]))
    assert setup_task_logger(parsed)
    assert not setup_task_logger(parsed)
    cancel_task_logger(task,'interrupted','No retry')
    assert not setup_task_logger(parsed)
    assert logged_in(web,alice).get('/api/v1/tasks/'+task).json['status'] == 'interrupted'
    assert logged_in(web,alice).get('/api/v1/tasks/'+task+'/summary').status_code == 422
    source=Path('website/web.py').read_text()
    assert '.control.purge(' not in source


def test_housekeeping_marks_stale_running_only_and_never_requeues(env):
    from backend.maintenance import mark_interrupted_tasks
    web, db, alice, *_ = env
    now=datetime.utcnow()
    stale=str(uuid4()); queued=str(uuid4()); active=str(uuid4())
    for task,state,age in [(stale,'running',1000),(queued,'queued',1000),(active,'running',10)]:
        db.taskdblogs.insert_one({'task':task,'owner_id':str(alice.id),'status':state,
            'start':now-timedelta(seconds=age),'started_at':now-timedelta(seconds=age),'end':None})
    assert mark_interrupted_tasks(now) == 1
    assert db.taskdblogs.find_one({'task':stale})['status']=='interrupted'
    assert db.taskdblogs.find_one({'task':queued})['status']=='queued'
    assert db.taskdblogs.find_one({'task':active})['status']=='running'


def test_housekeeping_removes_only_old_stopped_project_boxes(env,tmp_path):
    from backend.maintenance import cleanup_finished_containers
    removed=[]
    now=datetime.now(timezone.utc)
    def box(name,age,image='url-sandbox-box'):
        return SimpleNamespace(name=name,attrs={'Config':{'Image':image},'State':{
            'FinishedAt':(now-timedelta(seconds=age)).isoformat()}},remove=lambda:removed.append(name))
    own='url-sandbox_box_'+str(uuid4())
    recent='url-sandbox_box_'+str(uuid4())
    other='url-sandbox_box_'+str(uuid4())
    containers=[box(own,60),box(recent,10),box(other,60,'other-image'),box('unrelated',60)]
    def listing(**kwargs):
        assert kwargs['filters']['status']=='exited'
        return containers
    client=SimpleNamespace(containers=SimpleNamespace(list=listing))
    assert cleanup_finished_containers(client,str(tmp_path),now)==1
    assert removed==[own]


def test_failed_execution_is_visible_and_not_reported_as_success(env):
    from shared.logger import setup_task_logger,cancel_task_logger
    web,db,alice,*_=env
    task=str(uuid4())
    db.taskdblogs.insert_one({'task':task,'owner_id':str(alice.id),'status':'queued',
                             'start':datetime.utcnow(),'end':None,'logs':[]})
    assert setup_task_logger({'task':task,'owner_id':str(alice.id)})
    cancel_task_logger(task,'failed','Container failed')
    client=logged_in(web,alice)
    assert client.get('/api/v1/tasks/'+task).json['status']=='failed'
    assert client.get('/api/v1/tasks/'+task+'/summary').status_code==422
    assert b'Failed' in client.get('/queue/').data


def test_deleted_task_is_never_recreated_by_broker_replay(env):
    from shared.logger import setup_task_logger
    _,db,alice,*_=env
    task=str(uuid4())
    assert not setup_task_logger({'task':task,'owner_id':str(alice.id)})
    assert not db.taskdblogs.find_one({'task':task})


def test_celery_configuration_materializes_without_legacy_name_conflicts():
    from celery import Celery
    tree=ast.parse(Path('backend/worker.py').read_text())
    call=next(node for node in ast.walk(tree) if isinstance(node,ast.Call)
        and isinstance(node.func,ast.Attribute) and ast.unparse(node.func)=='CELERY.conf.update')
    config={keyword.arg:ast.literal_eval(keyword.value) for keyword in call.keywords}
    app=Celery('configuration-test')
    app.conf.update(**config)
    assert app.conf.task_acks_late is False
    assert app.conf.task_reject_on_worker_lost is False
    assert app.conf.accept_content==['json']


@pytest.mark.parametrize('typed, stored, fallback', [
    ('example.com/path?q=1', 'https://example.com/path?q=1', True),
    ('  example.com  ', 'https://example.com', True),
    ('http://example.com', 'http://example.com', False),
    ('HTTPS://example.com', 'HTTPS://example.com', False),
])
def test_targets_without_scheme_assume_https_and_flag_fallback(env, typed, stored, fallback):
    web, _, alice, _, dispatched = env
    form = {'buffer': typed, 'useragents': 'Chrome', 'urltimeout': '10',
            'analyzertimeout': '60', 'interactivetimeout': '300'}
    assert logged_in(web, alice).post('/url/', data=form).status_code == 302
    assert logged_in(web, alice).post('/api/v1/analyze', json={'url': typed}).status_code == 201
    for call in dispatched:
        assert call['args'][0]['buffer'] == stored
        assert call['args'][0]['scheme_fallback'] is fallback


def test_sandbox_falls_back_to_http_only_for_assumed_scheme():
    from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException
    from test_performance import load_functions
    calls = []

    class Response:
        history, headers, status_code = [], {}, 200
        request = SimpleNamespace(headers={})
        def close(self): pass

    def rget(url, **kwargs):
        calls.append(url)
        if url.startswith('https://'):
            raise RequestsConnectionError('TLS handshake failed')
        return Response()

    rows = []
    namespace = load_functions('box/qbsandbox.py', ['get_headers'], {
        'rget': rget, 'RequestException': RequestException, 'get_cert': lambda *a: None})
    table = SimpleNamespace(insert_multiple=rows.extend)
    assumed = {'buffer': 'https://example.com', 'scheme_fallback': True, 'useragent_mapped': 'UA'}
    namespace['get_headers'](assumed, table)
    assert calls == ['https://example.com', 'http://example.com']
    assert assumed['buffer'] == 'http://example.com' and rows

    calls.clear()
    typed = {'buffer': 'https://example.com', 'scheme_fallback': False, 'useragent_mapped': 'UA'}
    namespace['get_headers'](typed, table)
    assert calls == ['https://example.com'] and typed['buffer'] == 'https://example.com'


def test_analyze_and_wait_opens_the_task_report(env):
    web, _, alice, _, dispatched = env
    client = logged_in(web, alice)
    response = client.post('/url/', data={'buffer': 'example.com', 'useragents': 'Chrome', 'urltimeout': '10',
                                          'analyzertimeout': '60', 'interactivetimeout': '300',
                                          'submitandwait': 'Analyze & Wait'})
    task = dispatched[0]['args'][0]['task']
    assert response.status_code == 302 and response.headers['Location'].endswith('/report/' + task)
    page = client.get('/report/' + task)
    assert page.status_code == 200 and b'Waiting for a free sandbox' in page.data


def test_report_json_keeps_non_ascii_text_readable():
    from json import dumps, loads
    from test_performance import load_functions
    pretty_json = load_functions('backend/qbreport.py', ['pretty_json'], {'dumps': dumps})['pretty_json']
    rendered = pretty_json({'page_title': 'Marco Iannacone — Technology | Pippo.com'})
    assert '—' in rendered and '\\u2014' not in rendered
    assert loads(rendered)['page_title'] == 'Marco Iannacone — Technology | Pippo.com'


def test_task_status_is_never_cached(env):
    web, db, alice, _, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'start': datetime.utcnow(),
                              'end': None, 'logs': [], 'status': 'running'})
    response = logged_in(web, alice).get('/api/v1/tasks/' + task)
    assert response.status_code == 200 and response.json['status'] == 'running'
    assert response.headers['Cache-Control'] == 'no-store'
