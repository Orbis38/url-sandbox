import ast
from binascii import hexlify
from datetime import datetime
import json
import os
from pathlib import Path
import runpy
from types import ModuleType, SimpleNamespace
from uuid import UUID, uuid4

from assessment_helpers import ROOT


def test_worker_mounts_only_task_directory_and_preserves_settings(env):
    from shared.logger import setup_task_logger, cancel_task_logger, log_string, ignore_exception
    from shared.security import validate_timeouts
    from shared.reachability import failure_message
    web, db, alice, _, _ = env
    launched = []
    def missing(*args): raise KeyError('not found')
    class Container:
        status = 'exited'
        def reload(self): pass
        def logs(self): return b'Done!!'
        def stop(self): pass
        def remove(self): pass
    def run(*args, **kwargs):
        launched.append(kwargs)
        return Container()
    docker = SimpleNamespace(
        containers=SimpleNamespace(get=missing, run=run),
        volumes=SimpleNamespace(get=lambda name: SimpleNamespace(attrs={'Mountpoint': '/host/artifacts'})))
    namespace = dict(setup_task_logger=setup_task_logger, cancel_task_logger=cancel_task_logger,
        log_string=log_string, ignore_exception=ignore_exception, DOCKER_CLIENT=docker,
        json_settings=web.json_settings, environ={'project_env': 'docker'}, path=os.path,
        makedirs=os.makedirs, UUID=UUID, textract=lambda _: SimpleNamespace(domain='example', suffix='com'),
        hexlify=hexlify, jdumps=json.dumps, make_report=lambda p: None,
        release_vnc_port=lambda p: None, sleep=lambda s: None, validate_timeouts=validate_timeouts,
        failure_message=failure_message)
    source = ast.parse((ROOT / 'backend/worker.py').read_text())
    node = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'analyze_url')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'worker', 'exec'), namespace)
    tasks = [str(uuid4()), str(uuid4())]
    for task in tasks:
        db.taskdblogs.insert_one({'task':task,'owner_id':str(alice.id),'status':'queued',
                                 'start':datetime.utcnow(),'end':None,'logs':[]})
        namespace['analyze_url'](None, {'task': task, 'owner_id': str(alice.id), 'buffer': 'https://example.com',
            'interactive': False, 'use_proxy': False, 'analyzer_timeout': 30})
    assert len(launched) == 2
    for task, launch in zip(tasks, launched):
        assert launch['volumes'] == {f'/host/artifacts/{task}': {'bind': f'/output/{task}', 'mode': 'rw'}}
    assert web.json_settings['docker']['task_logs']['box_output'] == '/output/'


def test_box_output_and_report_use_same_per_task_directory(env, tmp_path, monkeypatch):
    web, db, alice, _, _ = env
    task = str(uuid4())
    parsed = {'task': task, 'owner_id': str(alice.id), 'use_proxy': False, 'sniffer_on': False,
              'buffer': 'https://example.com', 'locations': dict(web.json_settings['docker']['task_logs'])}
    parsed['locations']['box_output'] = str(tmp_path)
    sandbox = ModuleType('qbsandbox')
    def analyze(parsed, database):
        database.table('extracted_table').insert({'extracted_links': [{'link': 'https://example.com', 'text': '<script>alert(1)</script>'}]})
        database.close()
    sandbox.chrome_driver = analyze
    sniffer = ModuleType('qbsniffer')
    sniffer.QSniffer = object
    monkeypatch.setitem(__import__('sys').modules, 'qbsandbox', sandbox)
    monkeypatch.setitem(__import__('sys').modules, 'qbsniffer', sniffer)
    monkeypatch.setattr(__import__('sys'), 'argv', ['run.py', hexlify(json.dumps(parsed).encode()).decode()])
    runpy.run_path(str(ROOT / 'box/run.py'))
    assert (tmp_path / task / (task + '-analyzer.logs')).exists()
    assert not (tmp_path / (task + '-analyzer.logs')).exists()
    db.taskdblogs.insert_one(dict(parsed, start=datetime.utcnow(), logs=['OWNED_LOG']))
    from backend.qbreport import make_report
    monkeypatch.chdir(ROOT / 'backend')
    make_report(parsed)
    assert db.reports.find_one({'task': task, 'type': 'text/html'})
    html = web.get_it_fs('urlsandbox', {'task': task, 'contentType': 'text/html'})
    assert b'&lt;script&gt;' in html
    assert b'<script>alert(1)</script>' not in html


import pytest


@pytest.mark.parametrize('interactive', [False, True])
def test_unreachable_page_fails_the_task_even_when_interactive(env, tmp_path, interactive):
    from shared.logger import setup_task_logger, cancel_task_logger, log_string, ignore_exception
    from shared.security import validate_timeouts
    from shared.reachability import failure_message
    web, db, alice, _, _ = env
    task = str(uuid4())
    (tmp_path / task).mkdir()
    (tmp_path / task / 'analysis.done').write_text('')  # interactive: initial analysis finished
    class Container:
        status = 'running' if interactive else 'exited'
        def reload(self): pass
        def logs(self): return b'Done!!'
        def stop(self): pass
        def remove(self): pass
    docker = SimpleNamespace(
        containers=SimpleNamespace(get=lambda *a: (_ for _ in ()).throw(KeyError('none')), run=lambda *a, **kw: Container()),
        volumes=SimpleNamespace(get=lambda name: SimpleNamespace(attrs={'Mountpoint': str(tmp_path)})))
    unreachable = {'reachable': False, 'via_tor': True, 'tor_ok': True, 'page_loaded': False,
                   'reason': 'the site did not answer in time'}
    namespace = dict(setup_task_logger=setup_task_logger, cancel_task_logger=cancel_task_logger,
        log_string=log_string, ignore_exception=ignore_exception, DOCKER_CLIENT=docker,
        json_settings=web.json_settings, environ={'project_env': 'docker'}, path=os.path,
        makedirs=os.makedirs, UUID=UUID, textract=lambda _: SimpleNamespace(domain='pippo', suffix='com'),
        hexlify=hexlify, jdumps=json.dumps, make_report=lambda p: unreachable, find_free_port=lambda *a: 6080,
        release_vnc_port=lambda p: None, sleep=lambda s: None, validate_timeouts=validate_timeouts,
        failure_message=failure_message)
    source = ast.parse((ROOT / 'backend/worker.py').read_text())
    node = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'analyze_url')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'worker', 'exec'), namespace)
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'status': 'queued',
                              'start': datetime.utcnow(), 'end': None, 'logs': []})
    namespace['analyze_url'](None, {'task': task, 'owner_id': str(alice.id), 'buffer': 'https://pippo.com',
        'interactive': interactive, 'use_proxy': True, 'analyzer_timeout': 30})
    doc = db.taskdblogs.find_one({'task': task})
    assert doc['status'] == 'failed'
    assert doc['error'].startswith('The site did not respond through Tor')
