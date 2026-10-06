"""Exercise the real Flask routes; external MongoDB/Celery are isolated doubles."""
import importlib

import mongomock
import mongomock.gridfs
import pytest


@pytest.fixture(scope='session')
def web():
    patch = pytest.MonkeyPatch()
    patch.setenv('project_env', 'docker')
    import pymongo
    import mongoengine.connection
    from celery.app.control import Control
    from shared.settings import json_settings
    client = mongomock.MongoClient()
    mongomock.gridfs.enable_gridfs_integration()
    patch.setattr(pymongo, 'MongoClient', lambda *a, **kw: client)
    patch.setattr(mongoengine.connection, 'MongoClient', lambda *a, **kw: client)
    patch.setattr(Control, 'purge', lambda *a, **kw: 0)
    patch.setitem(json_settings['docker'], 'web_mongo', [{
        'ALIAS': 'default', 'DB': 'urlsandbox', 'HOST': 'mongodb://localhost/urlsandbox'}])
    module = importlib.import_module('website.web')
    module.APP.config.update(TESTING=True)
    yield module
    patch.undo()


@pytest.fixture
def env(web, monkeypatch, tmp_path):
    db = web.CLIENT['urlsandbox']
    for name in db.list_collection_names():
        db[name].delete_many({})
    alice = web.User(login='alice', password='unused').save()
    bob = web.User(login='bob', password='unused').save()
    monkeypatch.setitem(web.APP.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setitem(web.json_settings['docker'], 'output_folder', str(tmp_path))
    # Original worker mutates this dict; keep baseline reproductions test-local.
    monkeypatch.setitem(web.json_settings['docker'], 'task_logs', {
        'box_output': '/output/', 'sniffer_logs': '-sniffer.logs', 'analyzer_logs': '-analyzer.logs'})
    dispatched = []
    monkeypatch.setattr(web.CELERY, 'send_task', lambda *a, **kw: dispatched.append(kw))
    return web, db, alice, bob, dispatched


def logged_in(web, user):
    client = web.APP.test_client()
    with client.session_transaction() as session:
        session['_user_id'] = str(user.id)
        session['_fresh'] = True
        session['navs'] = []
    return client


@pytest.fixture(scope='session')
def original_web(web):
    import importlib.util
    import sys
    from types import ModuleType
    from assessment_helpers import ROOT, original_source
    module = ModuleType('website.assessment_baseline')
    module.__file__ = str(ROOT / 'website/web.py')
    module.__spec__ = importlib.util.spec_from_file_location(module.__name__, module.__file__)
    sys.modules[module.__name__] = module
    exec(compile(original_source('website/web.py'), module.__file__, 'exec'), module.__dict__)
    module.APP.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield module
    sys.modules.pop(module.__name__, None)
