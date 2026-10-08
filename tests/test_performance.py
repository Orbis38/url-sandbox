"""Contract tests for batching, binary artifacts and incremental, owner-scoped reads."""
import ast
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from io import BytesIO
import json
from pathlib import Path
from threading import Barrier, Lock, Event
from types import SimpleNamespace
from uuid import uuid4

from PIL import Image
import pytest
from tinydb import TinyDB
from tinydb.storages import Storage

from assessment_helpers import ROOT
from conftest import logged_in
from shared.artifacts import save_image, read_image, preview_jpeg
from shared.apikeys import create_api_key


def load_functions(filename, names, namespace):
    tree = ast.parse((ROOT / filename).read_text())
    for name in names:
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
        exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    return namespace


def png(color='red'):
    buffer = BytesIO()
    Image.new('RGB', (40, 30), color).save(buffer, 'PNG')
    return buffer.getvalue()


class CountingStorage(Storage):
    def __init__(self):
        self.data = None
        self.writes = 0
        self.bytes = 0
    def read(self): return self.data
    def write(self, data):
        self.bytes += len(json.dumps(data).encode())
        self.writes += 1
        self.data = data


def test_event_parser_batches_and_skips_malformed_records():
    db = TinyDB(storage=CountingStorage)
    namespace = load_functions('box/qbsandbox.py', ['find_key', 'parse_ouput'], {'loads': json.loads})
    logs = [{'message': json.dumps({'message': {'method': 'Network.requestWillBeSent',
            'params': {'headers': {'Host': 'example.com', 'X-Test': 'x' * 256}}}})} for _ in range(200)]
    logs.insert(100, {'message': 'not JSON'})
    namespace['parse_ouput'](logs, db.table('analyzer_table'))
    assert db.storage.writes == 1
    assert len(db.table('analyzer_table')) == 200
    assert db.storage.bytes < 100 * 1024


def test_screenshot_helpers_keep_binary_bytes_out_of_json(tmp_path):
    namespace = load_functions('box/qbsandbox.py',
        ['make_ai_screenshot_jpeg', 'take_normal_screen_shot', 'take_full_screen_shot'],
        {'save_image': save_image, 'preview_jpeg': preview_jpeg})
    raw = png()
    db = TinyDB(str(tmp_path / 'analysis.json'))
    driver = SimpleNamespace(get_screenshot_as_png=lambda: raw,
        find_element=lambda *args: SimpleNamespace(screenshot_as_png=raw))
    namespace['By'] = SimpleNamespace(TAG_NAME='tag name')
    namespace['take_normal_screen_shot'](driver, db.table('screenshot_table'), str(tmp_path))
    namespace['take_full_screen_shot'](driver, db.table('screenshot_table'), str(tmp_path))
    records = db.table('screenshot_table').all()
    assert records[0]['normal_image']['artifact'] == 'normal.png'
    assert (tmp_path / 'normal.png').read_bytes() == raw
    assert (tmp_path / 'full.png').read_bytes() == raw
    assert (tmp_path / 'ai.jpg').read_bytes().startswith(b'\xff\xd8')
    assert raw.hex() not in (tmp_path / 'analysis.json').read_text()
    assert len((tmp_path / 'analysis.json').read_bytes()) < 1024


def test_dns_records_resolve_concurrently():
    from concurrent.futures import ThreadPoolExecutor
    barrier = Barrier(8)
    calls = []
    def resolve(domain, kind, **kwargs):
        assert kwargs['lifetime'] == 5
        calls.append(kind)
        barrier.wait(timeout=3)
        return SimpleNamespace(rrset=SimpleNamespace(to_text=lambda: kind))
    rows = []
    namespace = load_functions('box/qbsandbox.py', ['get_dns'],
        {'resolve': resolve, 'ThreadPoolExecutor': ThreadPoolExecutor})
    namespace['get_dns']({'domain': 'example.com'}, SimpleNamespace(insert=rows.append))
    assert len(calls) == 8
    assert len(rows[0]['dns_records']) == 8


def test_sniffer_batches_and_flushes_tail_without_per_packet_writes():
    tree = ast.parse((ROOT / 'box/qbsniffer.py').read_text())
    original = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'QSniffer')
    methods = [n for n in original.body if isinstance(n, ast.FunctionDef)
               and n.name in ('add_packet', 'flush_packets')]
    wrapper = ast.parse('class Buffer:\n    pass').body[0]
    wrapper.body = methods
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[])), 'sniffer_buffer', 'exec'), namespace)
    buffer = namespace['Buffer']()
    buffer.pending = []
    buffer.pending_lock = Lock()
    buffer.flush_event = Event()
    batches = []
    buffer.logs = SimpleNamespace(insert_multiple=batches.append)
    for index in range(150): buffer.add_packet({'packet': index})
    assert not batches and buffer.flush_event.is_set()
    buffer.flush_packets()
    buffer.add_packet({'packet': 150})
    buffer.flush_packets()
    assert [len(batch) for batch in batches] == [150, 1]
    assert len({row['packet'] for batch in batches for row in batch}) == 151


def build_report(env, tmp_path, monkeypatch, inline=False):
    web, db, alice, bob, _ = env
    task = str(uuid4())
    task_dir = tmp_path / task
    task_dir.mkdir()
    normal, full, ai = png(), png('blue'), preview_jpeg(png())
    analyzer = TinyDB(str(task_dir / (task + '-analyzer.logs')))
    if inline:
        record = {'normal_image': normal.hex(), 'full_image': full.hex(), 'ai_image_jpeg': ai.hex()}
    else:
        record = {kind: save_image(str(task_dir), kind, payload) for kind, payload in
                  [('normal_image', normal), ('full_image', full), ('ai_image_jpeg', ai)]}
    analyzer.table('screenshot_table').insert(record)
    analyzer.table('extracted_table').insert({'ai_heuristics': {'page_title': 'Page title'}})
    analyzer.close()
    parsed = {'task': task, 'owner_id': str(alice.id), 'buffer': 'https://example.com',
              'locations': dict(web.json_settings['docker']['task_logs'], box_output=str(tmp_path))}
    db.taskdblogs.insert_one(dict(parsed, start=datetime.utcnow(), end=None, logs=[]))
    from backend.qbreport import make_report
    monkeypatch.chdir(ROOT / 'backend')
    make_report(parsed)
    db.taskdblogs.update_one({'task': task}, {'$set': {'end': datetime.utcnow()}})
    return task, normal, full, ai


@pytest.mark.parametrize('inline', [False, True])
def test_binary_report_preserves_default_api_base64_and_ownership(env, tmp_path, monkeypatch, inline):
    web, db, alice, bob, _ = env
    task, normal, full, ai = build_report(env, tmp_path, monkeypatch, inline)
    raw = web.get_it_fs('urlsandbox', {'task': task, 'contentType': 'application/json'})
    summary = web.get_it_fs('urlsandbox', {'task': task, 'contentType': 'application/json; type=ai_summary'})
    html = web.get_it_fs('urlsandbox', {'task': task, 'contentType': 'text/html'})
    assert normal.hex().encode() not in raw
    assert b'screenshot_base64' not in summary
    assert b'data:image/' not in html
    assert f'/api/v1/tasks/{task}/images/normal_image'.encode() in html
    assert db.artifacts.count_documents({'task': task}) == 3
    client = logged_in(web, alice)
    response = client.get(f'/api/v1/tasks/{task}/summary')
    assert response.status_code == 200
    assert response.json['page_content']['page_title'] == 'Page title'
    data_url = response.json['screenshot_base64']
    assert data_url.startswith('data:image/jpeg;base64,')
    assert b64decode(data_url.split(',', 1)[1]) == ai
    assert client.get(f'/api/v1/tasks/{task}/images/normal_image').data == normal
    assert client.get(f'/api/v1/tasks/{task}/images/full_image').data == full
    token = create_api_key(db.api_keys, str(alice.id), 'Image API')
    assert web.APP.test_client().get(f'/api/v1/tasks/{task}/images/normal_image',
                                    headers={'X-API-Key': token}).data == normal
    image = client.get(f'/api/v1/tasks/{task}/screenshot')
    assert image.data == ai and image.mimetype == 'image/jpeg'
    assert client.get(f'/api/v1/tasks/{task}/screenshot', headers={'If-None-Match': image.headers['ETag']}).status_code == 304
    assert logged_in(web, bob).get(f'/api/v1/tasks/{task}/images/normal_image',
                                   headers={'If-None-Match': image.headers['ETag']}).status_code == 404
    # The light response must not read or encode image bytes at all.
    monkeypatch.setattr(web, 'get_artifact', lambda *args: (_ for _ in ()).throw(AssertionError('image read')))
    light = client.get(f'/api/v1/tasks/{task}/summary?include_screenshot=false')
    assert light.status_code == 200 and 'screenshot_base64' not in light.json
    assert light.json['screenshot_url']


def test_image_update_changes_binary_and_preview_without_rewriting_report(env, tmp_path, monkeypatch):
    web, db, alice, _, _ = env
    task, _, _, _ = build_report(env, tmp_path, monkeypatch)
    report_id = db.reports.find_one({'task': task, 'type': 'text/html'})['file']
    original_html = web.get_it_fs('urlsandbox', {'_id': report_id})
    new = png('green')
    web.update_gridfs_report(task, b64encode(new).decode())
    assert db.reports.find_one({'task': task, 'type': 'text/html'})['file'] == report_id
    assert web.get_it_fs('urlsandbox', {'_id': report_id}) == original_html
    client = logged_in(web, alice)
    assert client.get(f'/api/v1/tasks/{task}/images/normal_image').data == new
    result = client.get(f'/api/v1/tasks/{task}/summary').json['screenshot_base64']
    image = Image.open(BytesIO(b64decode(result.split(',', 1)[1])))
    assert image.getpixel((0, 0))[1] > image.getpixel((0, 0))[0]
    assert db['fs.files'].count_documents({'task': task, 'artifact_kind': {'$exists': True}}) == 3


def test_image_descriptors_cannot_select_another_file(tmp_path):
    raw = png()
    descriptor = save_image(str(tmp_path), 'normal_image', raw)
    assert read_image(str(tmp_path), 'normal_image', descriptor)[0] == raw
    for name in ['../normal.png', '/etc/passwd', 'ai.jpg']:
        with pytest.raises(ValueError):
            read_image(str(tmp_path), 'normal_image', {'artifact': name})


def test_incremental_logs_scoped_bounded_and_without_duplicates(env):
    from shared.mongodbconn import update_task
    web, db, alice, bob, _ = env
    task = str(uuid4())
    foreign = str(uuid4())
    for task_id, owner in [(task, alice), (foreign, bob)]:
        db.taskdblogs.insert_one({'task': task_id, 'owner_id': str(owner.id), 'start': datetime.utcnow()})
    for index in range(205): update_task('urlsandbox', 'taskdblogs', task, f'line-{index}')
    update_task('urlsandbox', 'taskdblogs', foreign, 'BOB_SECRET')
    assert db.taskdblogs.find_one({'task': task}).get('logs', []) == []
    client = logged_in(web, alice)
    first = client.post('/activelogs/', json={'id': 0}).json
    assert first['reset'] and len(first['logs'].splitlines()) == 200
    assert 'BOB_SECRET' not in first['logs']
    unchanged = client.post('/activelogs/', json={'id': first['id']}).json
    assert unchanged['logs'] == '' and unchanged['id'] == first['id']
    update_task('urlsandbox', 'taskdblogs', task, 'NEW_ONLY')
    delta = client.post('/activelogs/', json={'id': first['id']}).json
    assert delta['logs'] == 'NEW_ONLY' and not delta['reset']
    for index in range(205): update_task('urlsandbox', 'taskdblogs', task, f'burst-{index}')
    page = client.post('/activelogs/', json={'id': delta['id']}).json
    assert page['has_more'] and len(page['logs'].splitlines()) == 200
    last = client.post('/activelogs/', json={'id': page['id']}).json
    assert len(last['logs'].splitlines()) == 5 and not last['has_more']
    assert client.post('/activelogs/', json={'id': {'$ne': None}}).status_code == 400
    full_log = client.get('/tasklog/' + task).data
    assert b'line-0' in full_log and b'NEW_ONLY' in full_log
    assert b'BOB_SECRET' not in full_log


def test_queue_projections_exclude_full_log_arrays(env, monkeypatch):
    web, db, alice, _, _ = env
    collection = db.taskdblogs
    collection.insert_one({'task': str(uuid4()), 'owner_id': str(alice.id), 'start': datetime.utcnow(),
                           'logs': ['large-log'] * 1000})
    original = collection.find
    observed = []
    def find(*args, **kwargs):
        records = list(original(*args, **kwargs))
        observed.extend(records)
        return original(*args, **kwargs)
    monkeypatch.setattr(collection, 'find', find)
    response = logged_in(web, alice).post('/queue/', json={})
    assert response.status_code == 200 and response.json['tasks'][0]['status'] == 'running'
    assert observed[0]['logs'] == ['large-log']


def test_retention_removes_new_artifacts_and_log_lines(env, tmp_path):
    from shared.mongodbconn import put_artifact, update_task
    from shared.retention import cleanup_expired_analyses
    web, db, alice, _, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id),
                             'start': datetime.utcnow() - timedelta(days=61)})
    file_id = put_artifact('urlsandbox', task, 'normal_image', png(), 'image/png')
    update_task('urlsandbox', 'taskdblogs', task, 'old log')
    assert cleanup_expired_analyses() == 1
    assert not db.artifacts.find_one({'task': task})
    assert not db.task_log_lines.find_one({'task': task})
    assert not db['fs.files'].find_one({'_id': file_id})


def test_indexes_cover_new_queries(env):
    web, db, *_ = env
    assert any(index['key'] == [('owner_id', 1), ('start', -1)] for index in db.taskdblogs.index_information().values())
    assert any(index['key'] == [('task', 1), ('kind', 1)] and index.get('unique') for index in db.artifacts.index_information().values())
