from datetime import datetime
from uuid import uuid4

import pytest
from bs4 import BeautifulSoup

from shared.apikeys import create_api_key, authenticate_api_key, revoke_api_key
from conftest import logged_in


def add_task(db, user, **extra):
    task_id = str(uuid4())
    db.taskdblogs.insert_one(dict(task=task_id, owner_id=str(user.id),
                                 start=datetime.utcnow(), end=None, logs=[], **extra))
    return task_id


def test_default_key_and_anonymous_rejected(env):
    web, db, alice, bob, dispatched = env
    client = web.APP.test_client()
    for headers in [{}, {'X-API-Key': 'urlsandbox_default_api_key_change_in_production'},
                    {'Authorization': 'Bearer urlsandbox_default_api_key_change_in_production'}]:
        assert client.post('/api/v1/analyze', json={'url': 'https://example.com'},
                           headers=headers).status_code == 401
    assert not dispatched


def test_tokens_hashed_unique_owned_and_revocable(env):
    web, db, alice, bob, _ = env
    token = create_api_key(db.api_keys, str(alice.id), 'Automation')
    second = create_api_key(db.api_keys, str(alice.id), 'Second')
    assert token != second
    record = db.api_keys.find_one({'label': 'Automation'})
    assert token not in str(record)
    assert authenticate_api_key(db.api_keys, token) == str(alice.id)
    assert db.api_keys.find_one({'_id': record['_id']})['last_used_at']
    assert not revoke_api_key(db.api_keys, str(bob.id), record['_id'])
    assert revoke_api_key(db.api_keys, str(alice.id), record['_id'])
    assert authenticate_api_key(db.api_keys, token) is None
    assert authenticate_api_key(db.api_keys, second) == str(alice.id)
    assert web.APP.test_client().post('/api/v1/analyze', json={'url': 'https://example.com'},
                                    headers={'X-API-Key': token}).status_code == 401


def test_key_screen_one_time_display_csrf_and_owner(env, monkeypatch):
    web, db, alice, bob, _ = env
    monkeypatch.setitem(web.APP.config, 'WTF_CSRF_ENABLED', True)
    client = logged_in(web, alice)
    page = client.get('/apikeys/')
    assert page.status_code == 200
    assert b'API Keys' in client.get('/queue/').data
    csrf = BeautifulSoup(page.data, 'html.parser').find('input', {'name': 'csrf_token'})['value']
    assert client.post('/apikeys/', data={'action': 'create', 'label': 'Missing CSRF'}).status_code == 400
    response = client.post('/apikeys/', data={'action': 'create', 'label': '<script>alert(1)</script>', 'csrf_token': csrf})
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    soup = BeautifulSoup(response.data, 'html.parser')
    token = next(code.text for code in soup.find_all('code') if len(code.text) > 40)
    assert token.startswith('usp_')
    assert token.encode() not in client.get('/apikeys/').data
    assert b'&lt;script&gt;' in response.data
    key = db.api_keys.find_one({'owner_id': str(alice.id)})
    other = logged_in(web, bob)
    other_page = other.get('/apikeys/')
    assert token.encode() not in other_page.data
    assert key['prefix'].encode() not in other_page.data
    csrf_bob = BeautifulSoup(other_page.data, 'html.parser').find('input', {'name': 'csrf_token'})['value']
    assert other.post('/apikeys/', data={'action': 'revoke', 'key_id': str(key['_id']),
                                        'csrf_token': csrf_bob}).status_code == 404
    assert client.post('/apikeys/', data={'action': 'revoke', 'key_id': str(key['_id']),
                                         'csrf_token': csrf}).status_code == 302
    assert authenticate_api_key(db.api_keys, token) is None


@pytest.mark.parametrize('bearer', [False, True])
def test_submission_assigns_authenticated_owner_before_dispatch(env, bearer):
    web, db, alice, bob, dispatched = env
    token = create_api_key(db.api_keys, str(alice.id), 'Submit')
    headers = {'Authorization': 'Bearer ' + token} if bearer else {'X-API-Key': token}
    client = web.APP.test_client()
    response = client.post('/api/v1/analyze', json={'url': 'https://example.com',
                                                  'owner_id': str(bob.id)}, headers=headers)
    assert response.status_code == 201
    task_id = response.json['task_id']
    assert db.taskdblogs.find_one({'task': task_id})['owner_id'] == str(alice.id)
    assert dispatched[0]['args'][0]['owner_id'] == str(alice.id)
    assert client.get('/api/v1/tasks/' + task_id, headers=headers).json['status'] == 'queued'


def test_web_submission_owned_and_scoped_queue_logs(env):
    web, db, alice, bob, dispatched = env
    client = logged_in(web, alice)
    response = client.post('/url/', data={'buffer': 'https://example.com', 'useragents': 'Chrome',
                                          'urltimeout': '10', 'analyzertimeout': '60',
                                          'interactivetimeout': '300'})
    assert response.status_code == 302
    assert dispatched[0]['args'][0]['owner_id'] == str(alice.id)
    alice_task = dispatched[0]['args'][0]['task']
    bob_task = add_task(db, bob, buffer='https://bob-secret.example')
    db.taskdblogs.update_one({'task': alice_task}, {'$set': {'logs': ['ALICE_ONLY']}})
    db.taskdblogs.update_one({'task': bob_task}, {'$set': {'logs': ['BOB_SECRET']}})
    db.taskdblogs.insert_one({'task': str(uuid4()), 'buffer': 'LEGACY_SECRET'})
    response = client.post('/queue/', json={})
    assert [row['task'] for row in response.json['tasks']] == [alice_task]
    assert b'BOB_SECRET' not in client.post('/activelogs/', json={'id': 0}).data
    assert b'ALICE_ONLY' in client.post('/activelogs/', json={'id': 0}).data
    assert b'bob-secret' not in client.get('/queue/').data
    response = client.post('/queue/', json={}, headers={'X-API-Key': 'invalid'})
    assert response.json['tasks'] == []


TASK_ROUTES = [
    ('GET', '/api/v1/tasks/{task}'), ('GET', '/api/v1/tasks/{task}/summary'),
    ('GET', '/api/v1/tasks/{task}/screenshot'), ('GET', '/api/v1/tasks/{task}/video'),
    ('GET', '/api/v1/tasks/{task}/images/normal_image'),
    ('GET', '/live_interact/{task}/status'), ('POST', '/live_interact/{task}'),
    ('GET', '/report/{task}'), ('GET', '/report/{task}/json'), ('GET', '/tasklog/{task}'),
]


@pytest.mark.parametrize('method,route', TASK_ROUTES)
@pytest.mark.parametrize('credential', ['session', 'api_key'])
def test_every_task_route_blocks_other_users(env, method, route, credential):
    web, db, alice, bob, _ = env
    task = add_task(db, alice)
    headers = {}
    if credential == 'session':
        client = logged_in(web, bob)
    else:
        client = web.APP.test_client()
        headers = {'X-API-Key': create_api_key(db.api_keys, str(bob.id), 'Other user')}
    response = client.open(route.format(task=task), method=method, json={'action': 'close'}, headers=headers)
    assert response.status_code == 404


def test_check_task_rejects_cross_user_and_nosql_injection(env):
    web, db, alice, bob, _ = env
    task = add_task(db, alice)
    client = logged_in(web, bob)
    for value in [task, {'$ne': None}, ['anything'], '..']:
        assert client.post('/task/', json={'task': value}).status_code == 404


def test_traversal_rejected_before_filesystem_access(env):
    web, db, alice, _, _ = env
    client = logged_in(web, alice)
    assert client.get('/api/v1/tasks/../video').status_code == 404
    assert client.get('/live_interact/../status').status_code == 404


def test_owner_can_read_reports_and_vnc_ticket(env, tmp_path):
    import json
    from gridfs import GridFS
    web, db, alice, bob, _ = env
    task = add_task(db, alice)
    fs = GridFS(db)
    fs.put(b'<html><body>PRIVATE_REPORT</body></html>', task=task, content_type='text/html')
    fs.put(json.dumps({'screenshot_table': {'normal_image': b'PNG_BYTES'.hex()}}).encode(),
           task=task, content_type='application/json')
    task_dir = tmp_path / task
    task_dir.mkdir()
    (task_dir / 'control.sock').touch()
    (task_dir / 'vnc_session.json').write_text(json.dumps({'status': 'active', 'vnc_token': 'secret-ticket', 'vnc_port': 6081}))
    (task_dir / 'session.mp4').write_bytes(b'VIDEO')
    client = logged_in(web, alice)
    assert b'PRIVATE_REPORT' in client.get('/report/' + task).data
    assert client.get('/api/v1/tasks/' + task + '/screenshot').data == b'PNG_BYTES'
    assert client.get('/api/v1/tasks/' + task + '/video').data == b'VIDEO'
    assert client.get('/live_interact/' + task + '/status').json['vnc_token'] == 'secret-ticket'
    assert logged_in(web, bob).get('/live_interact/' + task + '/status').status_code == 404


def test_worker_logger_does_not_duplicate_or_replace_owner(env):
    from shared.logger import setup_task_logger
    web, db, alice, bob, _ = env
    task = add_task(db, alice)
    setup_task_logger({'task': task, 'owner_id': str(bob.id)})
    assert db.taskdblogs.count_documents({'task': task}) == 1
    assert db.taskdblogs.find_one({'task': task})['owner_id'] == str(alice.id)


def test_explicit_bad_token_does_not_fall_back_to_cookie(env):
    web, db, alice, _, _ = env
    task = add_task(db, alice)
    assert logged_in(web, alice).get('/api/v1/tasks/' + task,
                                    headers={'Authorization': 'Bearer invalid'}).status_code == 401


def test_api_key_for_deleted_user_is_rejected(env):
    web, db, alice, _, _ = env
    token = create_api_key(db.api_keys, str(alice.id), 'Deleted account')
    alice.delete()
    assert web.APP.test_client().post('/api/v1/analyze', json={'url': 'https://example.com'},
                                     headers={'X-API-Key': token}).status_code == 401


def test_actual_login_succeeds_and_wrong_password_does_not(env):
    web, db, alice, _, _ = env
    alice.password = web.BCRYPT.generate_password_hash('alice-password').decode()
    alice.save()
    client = web.APP.test_client()
    assert client.post('/login/', data={'login': 'alice', 'password': 'wrong'}).status_code == 200
    assert client.get('/queue/').status_code == 302
    assert client.post('/login/', data={'login': 'alice', 'password': 'alice-password'}).status_code == 302
    assert client.get('/queue/').status_code == 200


def test_legacy_tasks_are_not_accessible(env):
    web, db, alice, _, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'start': datetime.utcnow(), 'logs': []})
    assert logged_in(web, alice).get('/api/v1/tasks/' + task).status_code == 404


def test_owned_completed_checktask_returns_report(env):
    from gridfs import GridFS
    web, db, alice, _, _ = env
    task = add_task(db, alice)
    db.taskdblogs.update_one({'task': task}, {'$set': {'end': datetime.utcnow()}})
    GridFS(db).put(b'<html><body>OWNED_REPORT</body></html>', task=task, content_type='text/html')
    assert logged_in(web, alice).post('/task/', json={'task': task}).data == b'OWNED_REPORT'
