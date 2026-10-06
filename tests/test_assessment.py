"""Positive tests document vulnerabilities; a passing test is NOT a clean bill of health."""
import ast
import importlib.util
from datetime import datetime, timedelta
from os import path
from pathlib import Path
import os
import shutil
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

from flask import Flask
from gridfs import GridFS
from jinja2 import Environment
import pytest

from assessment_helpers import ROOT, original_function, original_source
from conftest import logged_in

pytestmark = [pytest.mark.assessment, pytest.mark.skipif(
    os.environ.get('RUN_SECURITY_ASSESSMENT') != '1', reason='Explicit baseline assessment only')]


def test_baseline_default_key_accepted(env, original_web, monkeypatch):
    import shared.settings
    old_settings = {}
    exec(original_source('shared/settings.py'), old_settings)
    monkeypatch.setattr(shared.settings, 'API_KEY', old_settings['API_KEY'], raising=False)
    dispatched = []
    monkeypatch.setattr(original_web.CELERY, 'send_task', lambda *a, **kw: dispatched.append(kw))
    response = original_web.APP.test_client().post('/api/v1/analyze',
        headers={'X-API-Key': old_settings['API_KEY']}, json={'url': 'https://example.com'})
    assert response.status_code == 201 and dispatched


def test_known_session_secret_forges_identity_on_current_app(env):
    web, db, alice, bob, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'start': datetime.utcnow()})
    signer = web.APP.session_interface.get_signing_serializer(web.APP)
    forged = signer.dumps({'_user_id': str(alice.id), '_fresh': True})
    client = web.APP.test_client()
    client.set_cookie('localhost', web.APP.config['SESSION_COOKIE_NAME'], forged)
    assert client.get('/api/v1/tasks/' + task).status_code == 200


def test_baseline_cross_user_and_query_injection_return_private_report(env, original_web):
    web, db, alice, bob, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'start': datetime.utcnow(),
                             'end': datetime.utcnow(), 'logs': []})
    GridFS(db).put(b'<html><body>ALICE_PRIVATE</body></html>', task=task, content_type='text/html')
    client = logged_in(original_web, bob)
    assert b'ALICE_PRIVATE' in client.get('/report/' + task).data
    assert task in [row['task'] for row in client.post('/queue/').json['tasks']]
    assert b'ALICE_PRIVATE' in client.post('/task/', json={'task': {'$ne': None}}).data


def test_baseline_traversal_reads_only_fixed_named_parent_file(env, original_web, tmp_path):
    web, _, alice, _, _ = env
    output = tmp_path / 'output'
    output.mkdir()
    (tmp_path / 'session.mp4').write_bytes(b'PARENT_FILE')
    web.json_settings['docker']['output_folder'] = str(output)
    response = logged_in(original_web, alice).get('/api/v1/tasks/../video')
    assert response.status_code == 200 and response.data == b'PARENT_FILE'


def test_report_helpers_escape_adversarial_content():
    import json
    namespace = {'pretty_json': lambda v: json.dumps(v)}
    env = Environment(autoescape=True)
    env.filters['pretty_json'] = namespace['pretty_json']
    payload = '</pre><img src=x onerror="alert(1)"><script>alert(1)</script>{{7*7}}'
    for name, data in [('make_text_table', [payload]), ('make_json_table', [{'value': payload}]),
                       ('make_json_table_no_loop', {'value': payload})]:
        render = original_function('backend/qbreport.py', name, namespace)
        html = render(env, data, 'Test')
        assert '<script>alert(1)</script>' not in html
        assert '<img src=x' not in html
        assert '&lt;' in html and '{{7*7}}' in html


def test_vnc_reservations_are_not_atomic_even_with_redis(monkeypatch):
    reserved = set()
    class FakeRedis:
        def smembers(self, key): return {str(port).encode() for port in reserved}
        def srem(self, key, port): reserved.discard(int(port))
        def sadd(self, key, port):
            added = port not in reserved
            reserved.add(port)
            return int(added)
    import redis
    monkeypatch.setattr(redis, 'from_url', lambda url: FakeRedis())
    namespace = {'DOCKER_CLIENT': SimpleNamespace(containers=SimpleNamespace(list=lambda: [])),
                 'json_settings': {'docker': {'redis_settings': 'unused'}}, 'environ': {'project_env': 'docker'}}
    allocate = original_function('backend/worker.py', 'find_free_port', namespace)
    assert allocate() == 6080
    assert reserved == {6080}
    assert allocate() == 6080  # existing reservation is discarded before Docker has started


def test_failed_worker_job_is_marked_completed(env):
    from shared.logger import setup_task_logger, cancel_task_logger, log_string, ignore_exception
    web, db, alice, _, _ = env
    def fail(*args, **kwargs): raise RuntimeError('Simulated container startup failure')
    namespace = dict(setup_task_logger=setup_task_logger, cancel_task_logger=cancel_task_logger,
                     log_string=log_string, ignore_exception=ignore_exception,
                     DOCKER_CLIENT=SimpleNamespace(containers=SimpleNamespace(get=fail, run=fail)),
                     json_settings=web.json_settings, environ={'project_env': 'docker'}, path=path,
                     textract=lambda _: SimpleNamespace(domain='example', suffix='com'),
                     hexlify=lambda v: v.hex().encode(), jdumps=lambda v: '{}',
                     release_vnc_port=lambda p: None, make_report=fail)
    source = ast.parse(original_source('backend/worker.py'))
    node = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'analyze_url')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'baseline_worker', 'exec'), namespace)
    task = str(uuid4())
    namespace['analyze_url'](None, {'task': task, 'owner_id': str(alice.id), 'buffer': 'https://example.com',
                                   'interactive': False, 'use_proxy': False, 'analyzer_timeout': 30})
    doc = db.taskdblogs.find_one({'task': task})
    assert doc['end'] is not None
    assert not db.reports.find_one({'task': task})
    assert logged_in(web, alice).get('/api/v1/tasks/' + task).json['status'] == 'completed'


def test_retention_leaves_flat_log_artifacts(env, tmp_path):
    web, db, alice, _, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'start': datetime.utcnow() - timedelta(days=61)})
    (tmp_path / task).mkdir()
    flat = tmp_path / (task + '-analyzer.logs')
    flat.write_text('PRIVATE_DATA')
    namespace = dict(CLIENT=web.CLIENT, defaultdb=web.defaultdb, json_settings=web.json_settings,
                     environ={'project_env': 'docker'}, datetime=datetime, timedelta=timedelta,
                     GridFS=GridFS, path=path, shutil=shutil)
    cleanup = original_function('shared/retention.py', 'cleanup_expired_analyses', namespace)
    assert cleanup(project_env='docker') == 1
    assert not (tmp_path / task).exists()
    assert flat.read_text() == 'PRIVATE_DATA'


def test_low_timeout_limits_are_not_enforced(env, original_web, monkeypatch):
    _, _, alice, _, _ = env
    dispatched = []
    monkeypatch.setattr(original_web.CELERY, 'send_task', lambda *a, **kw: dispatched.append(kw))
    response = logged_in(original_web, alice).post('/api/v1/analyze', json={
        'url': 'https://example.com', 'interactive_timeout': 1000000000, 'url_timeout': -1})
    assert response.status_code == 201
    assert dispatched[0]['args'][0]['interactive_timeout'] == 1000000000


def test_open_redirect_is_real(env, original_web):
    _, _, alice, _, _ = env
    response = logged_in(original_web, alice).get('/login/?next=https://attacker.example/')
    assert response.status_code == 302
    assert response.headers['Location'] == 'https://attacker.example/'


def test_registration_accepts_one_character_password(env, original_web):
    response = original_web.APP.test_client().post('/register/', data={'login': 'weak', 'password': 'x'})
    assert response.status_code == 302
    assert original_web.User.objects(login='weak').first() is not None


def test_private_ip_literal_urls_are_rejected():
    from validator_collection import validators
    for url in ['http://127.0.0.1/private', 'http://192.168.1.10/private',
                'http://169.254.169.254/latest/meta-data/']:
        with pytest.raises(Exception):
            validators.url(url)


def test_cookie_api_post_ignores_csrf(env, original_web, monkeypatch):
    _, _, alice, _, _ = env
    monkeypatch.setitem(original_web.APP.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(original_web.CELERY, 'send_task', lambda *a, **kw: None)
    response = logged_in(original_web, alice).post('/api/v1/analyze',
        headers={'Origin': 'http://evil.localhost:9999'}, json={'url': 'https://example.com'})
    assert response.status_code == 201
    # This proves the server behavior; browser cookie delivery requires a separate browser test.
