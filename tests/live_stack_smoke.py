import base64
from datetime import datetime
from io import BytesIO
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import time
from uuid import uuid4

import docker
import requests
import websocket
from bs4 import BeautifulSoup
from PIL import Image

if os.environ.get('RUN_LIVE_STACK_TESTS') != '1':
    raise SystemExit('Set RUN_LIVE_STACK_TESTS=1 to test the deployed local stack with temporary accounts and tasks.')

BASE = 'http://127.0.0.1:8000'
RUN = uuid4().hex[:12]
CLIENT = docker.from_env()
WORKER = 'url-sandbox-workers_api-1'
OWN_LOGINS = [f'codex-smoke-{RUN}-alice', f'codex-smoke-{RUN}-bob']
TASKS = []
FIXTURE = None
CHECKS = []
STEP = 'startup'


def passed(name, **details):
    CHECKS.append(name)
    print(json.dumps({'check': name, 'result': 'PASS', **details}), flush=True)


def request(session, method, path, expected=200, **kwargs):
    response = session.request(method, BASE + path, timeout=30, **kwargs)
    if response.status_code != expected:
        raise RuntimeError(f'{method} {path.split("?")[0]}: HTTP {response.status_code}, expected {expected}')
    return response


def csrf(response):
    element = BeautifulSoup(response.content, 'html.parser').find('input', {'name': 'csrf_token'})
    assert element is not None, 'CSRF field absent'
    return element['value']


def create_user(login):
    session = requests.Session()
    form = request(session, 'GET', '/register/')
    response = request(session, 'POST', '/register/', expected=302, allow_redirects=False,
                       data={'login': login, 'password': secrets.token_urlsafe(24), 'csrf_token': csrf(form)})
    request(session, 'GET', '/queue/')
    return session


def create_key(session):
    page = request(session, 'GET', '/apikeys/')
    created = request(session, 'POST', '/apikeys/', data={'action': 'create', 'label': 'Temporary live smoke',
                                                       'csrf_token': csrf(page)})
    tokens = [element.text for element in BeautifulSoup(created.content, 'html.parser').find_all('code')
              if element.text.startswith('usp_') and len(element.text) > 40]
    assert len(tokens) == 1
    key = tokens[0]
    listed = request(session, 'GET', '/apikeys/')
    assert key.encode() not in listed.content
    soup = BeautifulSoup(listed.content, 'html.parser')
    key_id = soup.find('input', {'name': 'key_id'})['value']
    return key, key_id


def wait_task(session, task, timeout=150):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        status = request(session, 'GET', f'/api/v1/tasks/{task}').json()['status']
        if status != last:
            print(json.dumps({'task': task, 'state': status}), flush=True)
            last = status
        if status == 'completed':
            return request(session, 'GET', f'/api/v1/tasks/{task}/summary').json()
        if status in ('failed', 'timed_out', 'interrupted', 'cancelled'):
            raise RuntimeError('Analysis ended with status ' + status)
        time.sleep(1)
    raise TimeoutError('Analysis did not complete within smoke-test budget')


def verify_report(session, task, expected_width):
    summary = wait_task(session, task)
    assert summary['page_content']['page_title'] == 'URL Sandbox Smoke ' + RUN
    inline = summary['screenshot_base64']
    assert inline.startswith('data:image/jpeg;base64,')
    preview = base64.b64decode(inline.split(',', 1)[1], validate=True)
    Image.open(BytesIO(preview)).verify()
    light = request(session, 'GET', f'/api/v1/tasks/{task}/summary?include_screenshot=false').json()
    assert 'screenshot_base64' not in light and light['screenshot_url']
    normal = request(session, 'GET', f'/api/v1/tasks/{task}/images/normal_image')
    image = Image.open(BytesIO(normal.content))
    if expected_width == 1440:
        assert image.width == expected_width, f'Actual headless screenshot width: {image.width}'
    else:
        # A GUI screenshot covers page content, excluding window borders/toolbars.
        assert expected_width - 32 <= image.width <= expected_width
    assert 0 < image.height <= (900 if expected_width == 1440 else 720)
    full = request(session, 'GET', f'/api/v1/tasks/{task}/images/full_image')
    full_image = Image.open(BytesIO(full.content))
    full_size = list(full_image.size)
    assert full_image.height >= 1300 and full_image.height > image.height
    full_image.verify()
    request(session, 'GET', f'/api/v1/tasks/{task}/images/normal_image', expected=304,
            headers={'If-None-Match': normal.headers['ETag']})
    raw = request(session, 'GET', f'/report/{task}/json').json()
    assert raw['analyzer_table'], 'No browser network events captured'
    for row in raw['screenshot_table'].values():
        for value in row.values():
            assert isinstance(value, dict) and value.get('artifact') and value.get('url')
    report = request(session, 'GET', f'/report/{task}')
    assert f'/api/v1/tasks/{task}/images/normal_image'.encode() in report.content
    assert b'data:image/' not in report.content
    passed('report_api_images', task=task, original_size=list(image.size), preview_bytes=len(preview),
           network_events=len(raw['analyzer_table']), full_size=full_size)
    return raw


def verify_vnc(port, token):
    url = f'ws://127.0.0.1:{port}/websockify'
    for suffix in ['', '?token=invalid-token']:
        try:
            connection = websocket.create_connection(url + suffix, timeout=5, http_no_proxy=['127.0.0.1'])
        except (websocket.WebSocketBadStatusException, websocket.WebSocketConnectionClosedException):
            continue
        connection.close()
        raise AssertionError('VNC accepted an unauthorized WebSocket')
    connection = websocket.create_connection(url + '?token=' + token, timeout=10, http_no_proxy=['127.0.0.1'])
    buffer = b''
    def read(size):
        nonlocal buffer
        while len(buffer) < size:
            data = connection.recv()
            assert isinstance(data, bytes) and data
            buffer += data
        result, buffer = buffer[:size], buffer[size:]
        return result
    try:
        banner = read(12)
        assert banner == b'RFB 003.008\n'
        connection.send_binary(banner)
        count = read(1)[0]
        assert 1 in read(count)
        connection.send_binary(b'\x01')
        assert read(4) == b'\x00' * 4
        connection.send_binary(b'\x01')
        header = read(24)
        width, height = struct.unpack('>HH', header[:4])
        read(struct.unpack('>I', header[20:24])[0])
        assert (width, height) == (1280, 720)
        passed('live_vnc_auth_and_resolution', desktop=[width, height])
    finally:
        connection.close()


def cleanup():
    global FIXTURE
    for task in TASKS:
        try:
            CLIENT.containers.get('url-sandbox_box_' + task).remove(force=True)
        except docker.errors.NotFound:
            pass
    if FIXTURE is not None:
        FIXTURE.remove(force=True)
    cleanup_code = '''
import json, sys, re, shutil
from os import path, environ
from gridfs import GridFS
from shared.mongodbconn import CLIENT
from shared.settings import defaultdb, json_settings
names=json.loads(sys.stdin.read())
db=CLIENT[defaultdb['dbname']]
owners=[str(row['_id']) for row in db.users.find({'login': {'$in': names}}, {'_id':1})]
tasks=[row['task'] for row in db.taskdblogs.find({'owner_id':{'$in':owners}}, {'task':1})]
fs=GridFS(db)
for task in tasks:
    for file in fs.find({'task':task}): fs.delete(file._id)
    for collection in ['reports','taskfileslogs','artifacts','task_log_lines','taskdblogs']:
        db[collection].delete_many({'task':task})
    db.alllogs.delete_many({'message':{'$regex':re.escape(task)}})
    shutil.rmtree(path.join(json_settings[environ['project_env']]['output_folder'], task), ignore_errors=True)
db.api_keys.delete_many({'owner_id':{'$in':owners}})
db.users.delete_many({'login':{'$in':names}})
print(json.dumps({'temporary_accounts_removed':len(owners),'temporary_tasks_removed':len(tasks)}))
'''
    process = subprocess.run(['docker', 'exec', '-i', WORKER, 'python', '-c', cleanup_code],
                             input=json.dumps(OWN_LOGINS), text=True, capture_output=True, timeout=30)
    assert process.returncode == 0, 'Temporary database cleanup failed'
    print(process.stdout.strip(), flush=True)


def main():
    global FIXTURE, STEP
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            response = requests.get(BASE + '/login/', timeout=3)
            if response.status_code == 200: break
        except requests.RequestException: pass
        time.sleep(1)
    else: raise RuntimeError('Website did not become ready')
    passed('website_ready')
    STEP = 'temporary_accounts_and_api_keys'
    alice, bob = map(create_user, OWN_LOGINS)
    alice_key, alice_key_id = create_key(alice)
    bob_key, _ = create_key(bob)
    passed('real_registration_csrf_key_creation_one_time_display')
    anonymous = requests.Session()
    request(anonymous, 'POST', '/api/v1/analyze', expected=401,
            headers={'X-API-Key': 'urlsandbox_default_api_key_change_in_production'},
            json={'url': 'https://example.com'})
    passed('default_key_rejected')

    STEP = 'controlled_fixture'
    name = 'url-sandbox-smoke-' + RUN + '.test'
    server_code = f'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        html=b"""<html><head><title>URL Sandbox Smoke {RUN}</title></head>
<body style='font-family:sans-serif;background:#dfe9ff;min-height:1300px'>
<h1>Controlled local test {RUN}</h1><p>This is an isolated test page.</p>
<form><input name='username'><input type='password' name='password'></form>
<button onclick=\"document.getElementById('count').textContent='Clicked'\">Increment</button>
<p id='count'>Ready</p><a href='/next'>Next page</a></body></html>"""
        self.send_response(200); self.send_header('Content-Type','text/html')
        self.send_header('Content-Length',str(len(html))); self.end_headers(); self.wfile.write(html)
ThreadingHTTPServer(('0.0.0.0',8765),Handler).serve_forever()
'''
    FIXTURE = CLIENT.containers.run('python:3.11-slim', ['python', '-u', '-c', server_code],
        name=name, network='url-sandbox_frontend_box', detach=True,
        labels={'url-sandbox.smoke': RUN})
    url = f'http://{name}:8765/'

    STEP = 'headless_analysis'
    submitted = request(anonymous, 'POST', '/api/v1/analyze', expected=201,
        headers={'X-API-Key': alice_key}, json={'url': url, 'use_proxy': False,
            'take_screenshot': True, 'take_full_screenshot': True, 'sniffer_on': True,
            'analyzer_timeout': 120, 'url_timeout': 30}).json()
    task = submitted['task_id']; TASKS.append(task)
    raw = verify_report(alice, task, 1440)
    queue = request(alice, 'POST', '/queue/', json={}, headers={'X-CSRFToken': csrf(request(alice, 'GET', '/apikeys/'))}).json()
    assert task in [item['task'] for item in queue['tasks']]
    for suffix in ['', '/summary', '/screenshot', '/images/normal_image', '/video']:
        request(anonymous, 'GET', f'/api/v1/tasks/{task}' + suffix, expected=404, headers={'X-API-Key': bob_key})
    request(bob, 'GET', f'/report/{task}', expected=404)
    passed('real_user_isolation_and_api_key_scope')
    code = "import json;from pathlib import Path;from os import environ;from shared.mongodbconn import CLIENT;from shared.settings import defaultdb,json_settings;db=CLIENT[defaultdb['dbname']];task=" + repr(task) + ";data=json.loads((Path(json_settings[environ['project_env']]['output_folder'])/task/(task+'-sniffer.logs')).read_text());print(json.dumps({'captured_packets':len(data.get('sniffer_table',{})), 'log_lines':db.task_log_lines.count_documents({'task':task}), 'artifacts':db.artifacts.count_documents({'task':task}), 'owner_index':'owner_id_1_start_-1' in db.taskdblogs.index_information()}))"
    result = CLIENT.containers.get(WORKER).exec_run(['python', '-c', code])
    assert result.exit_code == 0
    counts = json.loads(result.output)
    assert counts['log_lines'] > 0 and counts['captured_packets'] > 0 and counts['owner_index']
    passed('database_real_indexes_artifacts_log_records', **counts)

    STEP = 'interactive_analysis_recording'
    interactive = request(alice, 'POST', '/api/v1/analyze', expected=201,
        json={'url': url, 'use_proxy': False, 'interactive': True, 'record_vnc': True,
            'take_screenshot': True, 'take_full_screenshot': True,
            'interactive_timeout': 300, 'analyzer_timeout': 120, 'url_timeout': 30}).json()['task_id']
    TASKS.append(interactive)
    verify_report(alice, interactive, 1280)
    state = request(alice, 'GET', f'/live_interact/{interactive}/status').json()
    assert state['active'] and state['vnc_token']
    verify_vnc(state['vnc_port'], state['vnc_token'])
    request(bob, 'GET', f'/live_interact/{interactive}/status', expected=404)
    time.sleep(2)
    closed = request(alice, 'POST', f'/live_interact/{interactive}', json={'action':'close'}).json()
    assert closed['status'] == 'ok'
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = request(alice, 'GET', f'/live_interact/{interactive}/status').json()
        container = CLIENT.containers.get('url-sandbox_box_' + interactive)
        container.reload()
        if container.status == 'exited' and state.get('has_video'): break
        time.sleep(1)
    else: raise RuntimeError('Interactive recording did not finalize')
    video = request(alice, 'GET', f'/api/v1/tasks/{interactive}/video')
    assert video.content[4:8] == b'ftyp'
    volume = CLIENT.volumes.get('url-sandbox_output').attrs['Mountpoint']
    probe = CLIENT.containers.run('url-sandbox-box',
        ['-v','error','-select_streams','v:0','-show_entries','stream=width,height,r_frame_rate','-of','json','/record/session.mp4'],
        entrypoint='ffprobe', volumes={volume+'/'+interactive:{'bind':'/record','mode':'ro'}},
        network_mode='none', remove=True)
    stream = json.loads(probe)['streams'][0]
    assert (stream['width'],stream['height']) == (1280,720)
    passed('interactive_close_video_finalized', recording=[stream['width'],stream['height']], fps=stream['r_frame_rate'])

    STEP = 'default_tor_analysis'
    tor_task = request(alice, 'POST', '/api/v1/analyze', expected=201,
        json={'url': 'https://example.com', 'analyzer_timeout': 120, 'url_timeout': 30}).json()['task_id']
    TASKS.append(tor_task)
    tor_summary = wait_task(alice, tor_task, timeout=180)
    assert tor_summary['page_content']['page_title'] == 'Example Domain', 'Tor navigation did not load the expected public test page'
    assert tor_summary['screenshot_base64'].startswith('data:image/jpeg;base64,')
    passed('default_tor_analysis')

    STEP = 'api_key_revocation'
    page = request(alice, 'GET', '/apikeys/')
    request(alice, 'POST', '/apikeys/', expected=302, allow_redirects=False,
            data={'action':'revoke','key_id':alice_key_id,'csrf_token':csrf(page)})
    request(anonymous, 'GET', f'/api/v1/tasks/{task}', expected=401, headers={'X-API-Key':alice_key})
    passed('real_api_key_revocation')


try:
    main()
    print(json.dumps({'result':'PASS','checks':CHECKS}), flush=True)
except Exception as exc:
    print(json.dumps({'result':'FAIL','step':STEP,'error_type':type(exc).__name__,
                      'message':str(exc)[:300]}), flush=True)
    for task in TASKS:
        code = "import json;from shared.mongodbconn import CLIENT;from shared.settings import defaultdb;rows=list(CLIENT[defaultdb['dbname']].task_log_lines.find({'task':" + repr(task) + "},{'message':1}).sort('_id',-1).limit(20));print('\\n'.join(row['message'] for row in reversed(rows)))"
        diagnostics = CLIENT.containers.get(WORKER).exec_run(['python','-c',code])
        print(diagnostics.output.decode('utf-8','replace'), flush=True)
        try:
            container = CLIENT.containers.get('url-sandbox_box_' + task)
            print(container.logs(tail=35).decode('utf-8','replace'), flush=True)
        except docker.errors.NotFound: pass
    raise
finally:
    cleanup()
