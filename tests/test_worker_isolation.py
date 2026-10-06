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
        release_vnc_port=lambda p: None, sleep=lambda s: None)
    source = ast.parse((ROOT / 'backend/worker.py').read_text())
    node = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'analyze_url')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'worker', 'exec'), namespace)
    tasks = [str(uuid4()), str(uuid4())]
    for task in tasks:
        namespace['analyze_url'](None, {'task': task, 'owner_id': str(alice.id), 'buffer': 'https://example.com',
            'interactive': False, 'use_proxy': False, 'analyzer_timeout': 30})
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
