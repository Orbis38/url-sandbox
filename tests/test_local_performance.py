"""Real TLS inspection and browser-executed polling tests on isolated services."""
import ast
from datetime import datetime, timedelta, timezone
import json
import os
import ssl
import sys
from threading import Event, Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
import requests
from tinydb import TinyDB
from tinydb.storages import MemoryStorage

from assessment_helpers import ROOT
from test_performance import load_functions
from test_local_security import chromium_dom

pytestmark = [pytest.mark.local_network, pytest.mark.skipif(
    os.environ.get('RUN_LOCAL_SECURITY_TESTS') != '1', reason='Opt-in local TLS/browser tests')]


@pytest.mark.parametrize('redirect', [False, True])
def test_http_and_certificate_share_streamed_request_without_body_download(tmp_path, redirect):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    finished = Event()
    calls = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_GET(self):
            calls.append(self.path)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/final')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Length', str(10 * 1024 * 1024))
            self.send_header('X-Test', 'inspection')
            self.end_headers()
            # Headers suffice. A full-body request would wait for this body or time out.
            finished.wait(timeout=10)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    responses = []
    def get(url, **kwargs):
        assert kwargs['stream'] is True
        response = requests.get(url, verify=str(cert_file), **kwargs)
        responses.append(response)
        return response
    def fail_on_error(*args):
        if 'failed' in str(args[0]):
            raise sys.exception()
    namespace = load_functions('box/qbsandbox.py', ['get_headers', 'get_cert'], {'rget': get, 'print': fail_on_error})
    db = TinyDB(storage=MemoryStorage)
    try:
        url = f'https://localhost:{server.server_port}/' + ('redirect' if redirect else 'final')
        namespace['get_headers']({'buffer': url, 'use_proxy': False, 'useragent_mapped': 'test'},
                                 db.table('extracted_table'))
        rows = db.table('extracted_table').all()
        assert len(calls) == (2 if redirect else 1)
        assert rows[1]['Response_Headers']['response_status'] == (302 if redirect else 200)
        assert rows[2]['Certificate']['Expired'] is False
        assert responses[0]._content is False
        assert responses[0].raw.closed
    finally:
        finished.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_polling_javascript_avoids_overlap_hidden_requests_and_duplicate_logs(tmp_path):
    queue = (ROOT / 'website/static/queue.js').read_text()
    logs = (ROOT / 'website/static/activelogs.js').read_text()
    script = r'''
    function check(ok, message) { if (!ok) throw new Error(message); }
    function run(source, isLogs) {
      var timers=[], calls=[], callbacks=[], value='', hidden=false;
      var box={0:{scrollHeight:1}, val:function(v){if(arguments.length)value=v;return value;},
               scrollTop:function(){}, height:function(){return 1;}, text:function(){}, html:function(){}};
      var $=function(selector){return selector===document?{ready:function(cb){callbacks.push(cb);}}:box;};
      $.ajaxSetup=function(){};
      $.ajax=function(options){calls.push(options);};
      var schedule=function(cb, delay){timers.push({callback:cb,delay:delay});};
      Object.defineProperty(document,'hidden',{configurable:true,get:function(){return hidden;}});
      new Function('$','csrf_token','setTimeout',source)($,'csrf',schedule);
      callbacks[0]();
      if(!isLogs)timers.shift().callback();
      check(calls.length===1,'initial request');
      check(timers.length===0,'in-flight request must not schedule overlapping polls');
      if(isLogs)calls[0].success({id:'cursor',logs:'line1',reset:true,has_more:false});
      else calls[0].success({kpis:{running:1,queued:0,total:1,completed:0},tasks:[]});
      calls[0].complete();
      check(timers[0].delay===(isLogs?1000:2000),'active delay');
      hidden=true;
      timers.shift().callback();
      check(calls.length===1 && timers[0].delay===5000,'hidden page must not request');
      hidden=false;
      timers.shift().callback();
      if(isLogs)calls[1].success({id:'cursor',logs:'',reset:false,has_more:false});
      else calls[1].success({kpis:{running:0,queued:0,total:0,completed:0},tasks:[]});
      calls[1].complete();
      check(timers[0].delay===(isLogs?3000:5000),'idle delay');
      if(isLogs) {
        check(value==='line1','unchanged logs must not be duplicated');
        timers.shift().callback();
        calls[2].success({id:'newcursor',logs:'line2',reset:false,has_more:false});
        calls[2].complete();
        check(value==='line1\nline2','append only delta');
      }
    }
    '''
    html = '<html><body><script>' + script + '\ntry { run(' + json.dumps(queue) + ',false); run(' + json.dumps(logs) + ",true); document.body.textContent='POLLING_PASS'; } catch(e) { document.body.textContent='FAIL '+e.message; }</script></body></html>"
    page = tmp_path / 'polling.html'
    page.write_text(html)
    dom = chromium_dom(page.as_uri(), tmp_path / 'chrome-profile')
    assert '<body>POLLING_PASS</body>' in dom
