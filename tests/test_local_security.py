"""Real loopback HTTP/WebSocket/browser tests; no production services are contacted."""
import ast
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests
import websocket
from validator_collection import validators
from werkzeug.serving import make_server

from assessment_helpers import ROOT, original_function, original_source

pytestmark = [pytest.mark.local_network, pytest.mark.skipif(
    os.environ.get('RUN_LOCAL_SECURITY_TESTS') != '1', reason='Opt-in loopback integration tests')]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture
def internal_http():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_HEAD(self):
            self.send_response(200)
            self.send_header('X-Internal-Secret', 'PRIVATE_SERVICE_REACHED')
            self.end_headers()
        def do_GET(self):
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/private')
                self.end_headers()
            else:
                body = b'<html><body>PRIVATE_SERVICE_REACHED</body></html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://localhost:{server.server_port}'
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def chromium_dom(url, profile):
    result = subprocess.run(['chromium', '--headless', '--no-sandbox', '--disable-gpu',
        '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking',
        '--disable-component-update', '--disable-sync', '--disable-extensions', '--no-first-run',
        '--no-default-browser-check', '--virtual-time-budget=5000', '--dump-dom',
        '--user-data-dir=' + str(profile), url], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout


@pytest.mark.assessment
def test_ssrf_reaches_real_loopback_http_service(internal_http):
    url = internal_http + '/private'
    assert validators.url(url) == url
    rows = []
    get_headers = original_function('box/qbsandbox.py', 'get_headers', {'rhead': requests.head})
    get_headers({'buffer': url, 'use_proxy': False, 'useragent_mapped': 'security-test'},
                SimpleNamespace(insert=rows.append))
    assert rows[-1]['Response_Headers']['X-Internal-Secret'] == 'PRIVATE_SERVICE_REACHED'


@pytest.mark.assessment
@pytest.mark.parametrize('no_redirect', [False, True])
def test_real_chromium_follows_redirect_in_both_baseline_branches(internal_http, tmp_path, no_redirect):
    source = ast.parse(original_source('box/qbsandbox.py'))
    chrome = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'chrome_driver')
    branch = next(n for n in chrome.body if isinstance(n, ast.If)
                  and ast.unparse(n.test) == "parsed['no_redirect']")
    wrapper = ast.parse('def navigate(chromebrowser, parsed):\n    pass').body[0]
    wrapper.body = [branch]
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[])),
                 'baseline_navigation', 'exec'), namespace)
    class Browser:
        def implicitly_wait(self, seconds): pass
        def get(self, url): self.dom = chromium_dom(url, tmp_path / 'chrome')
    browser = Browser()
    namespace['navigate'](browser, {'no_redirect': no_redirect, 'url_timeout': 5,
                                    'buffer': internal_http + '/redirect'})
    assert 'PRIVATE_SERVICE_REACHED' in browser.dom


@pytest.fixture
def echo_target():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    listener.settimeout(0.2)
    stop = threading.Event()
    def serve():
        while not stop.is_set():
            try: client, _ = listener.accept()
            except socket.timeout: continue
            except OSError: break
            with client:
                client.sendall(b'RFB 003.008\n')
                client.settimeout(0.2)
                try: client.recv(1024)
                except (socket.timeout, OSError): pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    listener.close()
    thread.join(timeout=3)


def start_websockify(port, args, target=None):
    command = [sys.executable, '-m', 'websockify', *args, f'127.0.0.1:{port}']
    if target:
        command.append(target)
    proc = subprocess.Popen(command,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert proc.poll() is None, 'websockify exited'
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                return proc
        except OSError: time.sleep(0.05)
    proc.terminate()
    proc.wait(timeout=3)
    raise AssertionError('websockify did not start')


def ws_connect(port, token=None):
    url = f'ws://127.0.0.1:{port}/websockify'
    if token is not None: url += '?token=' + token
    return websocket.create_connection(url, timeout=3, http_no_proxy=['127.0.0.1'])


def test_vnc_ticket_rejects_missing_wrong_and_other_session_tokens(tmp_path, echo_target):
    token_file = tmp_path / 'vnc.tokens'
    token_file.write_text(f'owner-session-ticket: localhost:{echo_target}\n')
    port = free_port()
    source = ast.parse((ROOT / 'box/qbsandbox.py').read_text())
    call = next(node for node in ast.walk(source) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == 'Popen'
                and node.args and isinstance(node.args[0], ast.List)
                and isinstance(node.args[0].elts[0], ast.Constant)
                and node.args[0].elts[0].value == 'websockify')
    command = eval(compile(ast.Expression(call.args[0]), 'websockify_command', 'eval'),
                   {'token_path': str(token_file)})
    assert command[-1] == '6080', 'Token plugin must provide the target; no positional target is allowed'
    args = [str(tmp_path) if arg == '/usr/share/novnc' else arg for arg in command[1:-1]]
    proc = start_websockify(port, args)
    try:
        for token in [None, 'wrong', 'other-user-session-ticket']:
            with pytest.raises((websocket.WebSocketBadStatusException,
                                websocket.WebSocketConnectionClosedException)):
                ws_connect(port, token)
        conn = ws_connect(port, 'owner-session-ticket')
        try: assert conn.recv() == b'RFB 003.008\n'
        finally: conn.close()
    finally:
        proc.terminate()
        proc.wait(timeout=3)


@pytest.mark.assessment
def test_original_websockify_accepts_no_credentials(echo_target):
    port = free_port()
    proc = subprocess.Popen([sys.executable, '-m', 'websockify', f'127.0.0.1:{port}',
                              f'localhost:{echo_target}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                conn = ws_connect(port)
                break
            except (ConnectionRefusedError, OSError):
                if time.monotonic() >= deadline: raise
                time.sleep(0.05)
        try: assert conn.recv() == b'RFB 003.008\n'
        finally: conn.close()
    finally:
        proc.terminate()
        proc.wait(timeout=3)


@pytest.mark.assessment
def test_cross_origin_json_csrf_is_blocked_by_real_browser(env, original_web, monkeypatch, tmp_path):
    _, _, alice, _, _ = env
    dispatched = []
    monkeypatch.setitem(original_web.APP.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(original_web.CELERY, 'send_task', lambda *a, **kw: dispatched.append(kw))
    cookie = original_web.APP.session_interface.get_signing_serializer(original_web.APP).dumps(
        {'_user_id': str(alice.id), '_fresh': True})
    attack_server = None
    def victim_app(environ, start_response):
        if environ['PATH_INFO'] == '/seed':
            start_response('302 Found', [('Set-Cookie', f'session={cookie}; Path=/; SameSite=Lax; HttpOnly'),
                                        ('Location', f'http://localhost:{attack_server.server_port}/')])
            return [b'']
        return original_web.APP(environ, start_response)
    victim = make_server('127.0.0.1', 0, victim_app, threaded=True)
    class Attack(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            html = f'''<html><body>WAITING<script>
            Promise.all([
              fetch('http://localhost:{victim.server_port}/api/v1/analyze', {{method:'POST', credentials:'include',
                headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{url:'https://example.com'}})}})
                .then(()=> 'unexpected').catch(()=> 'preflight-blocked'),
              fetch('http://localhost:{victim.server_port}/api/v1/analyze', {{method:'POST', mode:'no-cors', credentials:'include',
                headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{url:'https://example.com'}})}})
                .then(()=> 'opaque').catch(()=> 'blocked')
            ]).then(values=>document.body.textContent='DONE '+values.join(' '));
            </script></body></html>'''.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html)
    attack_server = ThreadingHTTPServer(('127.0.0.1', 0), Attack)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in [victim, attack_server]]
    for thread in threads: thread.start()
    try:
        dom = chromium_dom(f'http://localhost:{victim.server_port}/seed', tmp_path / 'csrf-profile')
        assert 'DONE preflight-blocked opaque' in dom
        assert not dispatched
    finally:
        for server in [victim, attack_server]: server.shutdown(); server.server_close()
        for thread in threads: thread.join(timeout=3)
