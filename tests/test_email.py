import ast
import io
import json
import os
import sys
import zipfile
from datetime import datetime
from email.message import EmailMessage
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from bs4 import BeautifulSoup

from assessment_helpers import ROOT
from conftest import logged_in

sys.path.insert(0, str(ROOT / 'mailbox'))
import qbmail  # noqa: E402


def phishing_message():
    message = EmailMessage()
    message['From'] = '"support@paypal.com" <alert@paypa1-secure.xyz>'
    message['To'] = 'victim@corp.example'
    message['Reply-To'] = 'collect@evil.example'
    message['Return-Path'] = '<bounce@mailer.evil.example>'
    message['Subject'] = '=?utf-8?q?Verifica_account_=E2=9C=85?='
    message['Date'] = 'Mon, 26 Oct 2026 10:00:00 +0000'
    message['Message-ID'] = '<abc@mx.evil.example>'
    message['Authentication-Results'] = ('mx.corp.example; spf=fail smtp.mailfrom=evil.example; dkim=none; '
                                         'dmarc=fail header.from=paypa1-secure.xyz')
    message['Received'] = ('from mx.corp.example (mx.corp.example [10.0.0.5]) by inbox.corp.example with ESMTPS '
                           'id 1; Mon, 26 Oct 2026 10:00:09 +0000')
    message['Received'] = ('from bad.host (unknown [185.220.101.4]) by mx.corp.example with ESMTP id 2 '
                           'for <victim@corp.example>; Mon, 26 Oct 2026 10:00:02 +0000')
    message.set_content('Visit https://paypa1-secure.xyz/login now.')
    message.add_alternative('''<html><head><style>.b{background:url(https://track.evil.example/bg.png)}
@import url(https://x.example/z.css);</style></head>
<body bgcolor="#eee" onload="alert(1)"><table background="https://evil.example/t.png"><tr><td>
<img src="cid:logo1"><img src="https://track.evil.example/p.gif?id=1" width=1 height=1>
<p>Hello <a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1-secure.xyz%2Flogin&data=x"
 target=_blank onclick="x()">https://www.paypal.com/signin</a></p>
<a href="javascript:alert(1)">click</a> <a href="http://185.220.101.4/x">ip</a>
<form action="https://evil.example/post"><input name=pw type=password></form>
<script>alert(1)</script><iframe src="https://evil.example"></iframe><svg><use href="https://evil.example/a.svg#x"/></svg>
<meta http-equiv="refresh" content="0;url=https://evil.example"><base href="https://evil.example/">
</td></tr></table></body></html>''', subtype='html')
    message.get_payload()[1].add_related(b'\x89PNG\r\n\x1a\n' + b'0' * 50, 'image', 'png', cid='<logo1>')
    message.add_attachment(b'MZ\x90\x00rest', maintype='application', subtype='pdf', filename='fattura.pdf.exe')
    document = io.BytesIO()
    with zipfile.ZipFile(document, 'w') as archive:
        archive.writestr('[Content_Types].xml', 'x')
        archive.writestr('word/vbaProject.bin', 'x')
    message.add_attachment(document.getvalue(), maintype='application', subtype='octet-stream', filename='doc.docm')
    message.add_attachment(b'<html><script>atob("x")</script></html>', maintype='text', subtype='html',
                           filename='invoice.html')
    return bytes(message)


def test_analysis_finds_phishing_indicators():
    analysis, _ = qbmail.analyze(phishing_message(), 'phish.eml')
    found = {item['id'] for item in analysis['indicators']}
    assert {'spf_fail', 'dmarc_fail', 'display_name_spoof', 'reply_to_mismatch', 'masked_links', 'script_links',
            'ip_links', 'html_form', 'remote_content', 'executable_attachment', 'double_extension',
            'macro_attachment', 'html_attachment'} <= found
    assert analysis['verdict'] == 'suspicious'
    assert analysis['message']['subject'] == 'Verifica account ✅'
    assert analysis['message']['from'] == {'name': 'support@paypal.com', 'address': 'alert@paypa1-secure.xyz'}
    wrapped = analysis['links'][0]
    assert wrapped['target'] == 'https://paypa1-secure.xyz/login'
    assert {'masked', 'wrapped'} <= set(wrapped['flags'])
    hops = analysis['received']
    assert hops[0]['public_ips'] == ['185.220.101.4'] and hops[1]['delay_seconds'] == 7
    assert analysis['iocs']['ips'] == ['185.220.101.4']
    assert 'javascript:alert(1)' not in analysis['iocs']['urls']
    by_name = {item['filename']: item for item in analysis['attachments']}
    assert 'contains_macros' in by_name['doc.docm']['flags']
    assert by_name['fattura.pdf.exe']['detected'] == 'pe'


def test_rendering_keeps_layout_but_nothing_runs_or_fetches():
    analysis, rendered = qbmail.analyze(phishing_message(), 'phish.eml')
    soup = BeautifulSoup(rendered, 'html.parser')
    for tag in ('script', 'iframe', 'meta[http-equiv]', 'base', 'link'):
        assert not soup.select(tag)
    assert soup.find('body')['bgcolor'] == '#eee' and soup.find('table')  # layout survives
    assert not any(name.startswith('on') for tag in soup.find_all(True) for name in tag.attrs)
    assert not soup.find('form').get('action')
    for tag in soup.find_all(True):
        for name, value in tag.attrs.items():
            text = ' '.join(value) if isinstance(value, list) else str(value)
            if name in ('src', 'href', 'background', 'action', 'style'):
                assert 'http' not in text and 'javascript:' not in text, (tag.name, name, text)
    assert 'evil.example' not in ''.join(str(tag) for tag in soup.find_all('style'))
    images = soup.find_all('img')
    assert images[0]['src'].startswith('data:image/png;base64,')  # cid: image inlined
    assert images[1]['data-up-blocked'] == 'track.evil.example'
    anchors = soup.find_all('a')
    assert anchors[0]['href'] == '#' and anchors[0]['data-up-link'] == '0' and 'target' not in anchors[0].attrs
    assert analysis['remote_content']['count'] >= 4


def test_plain_text_message_is_linkified_and_escaped():
    message = EmailMessage()
    message['From'] = 'a@example.com'
    message['Subject'] = 'text'
    message.set_content('<b>not html</b> go to www.example.org/path, then https://bit.ly/x.')
    analysis, rendered = qbmail.analyze(bytes(message), 'm.eml')
    assert '&lt;b&gt;not html&lt;/b&gt;' in rendered
    assert [link['target'] for link in analysis['links']] == ['http://www.example.org/path', 'https://bit.ly/x']
    assert 'shortener' in analysis['links'][1]['flags']
    assert rendered.count('data-up-link=') == 2


def test_unwrap_gateway_urls():
    assert qbmail.unwrap_url('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a&d=x') == \
        'https://evil.example/a'
    assert qbmail.unwrap_url('https://www.google.com/url?q=https://evil.example/&sa=D') == 'https://evil.example/'
    assert qbmail.unwrap_url('https://example.com/?url=x') == 'https://example.com/?url=x'


@pytest.mark.parametrize('raw,expected', [
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\0' * 100, 'input.msg'),
    (b'Received: from x\r\nFrom: a@b.c\r\nSubject: s\r\n\r\nbody', 'input.eml'),
    (b'From a@b Mon Jan 1\nFrom: a@b.c\nSubject: s\n\nbody', 'input.eml'),
    (b'MZ\x90\x00 not a message', None),
    (b'<html><body>hi</body></html>', None),
    (b'Content-Type: text/plain\n\nno mail header', None),
])
def test_only_email_messages_are_accepted(web, raw, expected):
    assert web.email_input_name(raw) == expected


def upload(client, raw, name='phish.eml', **extra):
    return client.post('/email/', data={'file': (io.BytesIO(raw), name), **extra},
                       content_type='multipart/form-data')


def test_upload_stores_message_and_queues_email_worker(env, tmp_path):
    web, db, alice, _, dispatched = env
    raw = phishing_message()
    response = upload(logged_in(web, alice), raw, name='..\\..\\evil\u202e.eml')
    assert response.status_code == 302
    task = db.taskdblogs.find_one({'type': 'email'})
    assert task['owner_id'] == str(alice.id) and task['input_name'] == 'input.eml'
    assert task['filename'] == 'evil.eml'
    assert (tmp_path / task['task'] / 'input.eml').read_bytes() == raw
    assert dispatched[0]['queue'] == 'analyze_url_queue'
    assert dispatched[0]['args'][0]['input_name'] == 'input.eml'


def test_upload_rejects_other_files_and_size_is_limited_elsewhere(env):
    web, db, alice, _, dispatched = env
    client = logged_in(web, alice)
    assert upload(client, b'MZ\x90\x00 evil', name='mail.eml').status_code == 400
    assert not dispatched and not db.taskdblogs.count_documents({})
    big = client.post('/api/v1/analyze', data=b'{"url": "' + b'a' * (2 * 1024 * 1024) + b'"}',
                      content_type='application/json')
    assert big.status_code == 413
    chunked = client.post('/api/v1/analyze', input_stream=io.BytesIO(b'{"url": "https://example.com"}'),
                          content_type='application/json', headers={'Transfer-Encoding': 'chunked'})
    assert chunked.status_code == 413 and not dispatched


def test_api_upload(env):
    web, db, alice, _, dispatched = env
    from shared.apikeys import create_api_key
    token = create_api_key(db['api_keys'], str(alice.id), 'soar')
    response = web.APP.test_client().post('/api/v1/analyze/email', headers={'X-API-Key': token},
                                          data={'file': (io.BytesIO(phishing_message()), 'm.eml')},
                                          content_type='multipart/form-data')
    assert response.status_code == 201 and response.json['type'] == 'email'
    assert dispatched[0]['args'][0]['task'] == response.json['task_id']


def stored_email_task(web, db, owner, tmp_path):
    from backend.qbmailreport import make_email_report
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(owner.id), 'type': 'email', 'status': 'completed',
                              'filename': 'phish.eml', 'input_name': 'input.eml', 'buffer': 'phish.eml',
                              'start': datetime.utcnow(), 'end': datetime.utcnow(), 'logs': []})
    analysis, rendered = qbmail.analyze(phishing_message(), 'phish.eml')
    out = tmp_path / task / 'mail'
    out.mkdir(parents=True)
    (tmp_path / task / 'input.eml').write_bytes(phishing_message())
    (out / 'email.json').write_text(json.dumps(analysis))
    (out / 'message.html').write_text(rendered)
    make_email_report({'task': task}, str(out))
    return task


def test_email_report_page_and_inert_message(env, tmp_path):
    web, db, alice, bob, _ = env
    task = stored_email_task(web, db, alice, tmp_path)
    client = logged_in(web, alice)
    page = client.get('/report/' + task)
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    soup = BeautifulSoup(html, 'html.parser')
    frame = soup.find('iframe', id='mail-frame')
    assert frame['sandbox'] == ['allow-same-origin'] and frame['src'] == f'/report/{task}/message'
    assert 'Verifica account' in soup.find('h1').text
    assert soup.find('form', id='sandbox-form').find('input', {'name': 'parent_task'})['value'] == task
    assert json.loads(soup.find('script', id='email-links').string)[0]['target'] == 'https://paypa1-secure.xyz/login'
    message = client.get(f'/report/{task}/message')
    assert message.status_code == 200 and message.mimetype == 'text/html'
    csp = message.headers['Content-Security-Policy']
    assert "script-src 'none'" in csp and "default-src 'none'" in csp and "frame-ancestors 'self'" in csp
    assert b'<script' not in message.data
    assert db.taskdblogs.find_one({'task': task})['subject'] == 'Verifica account ✅'
    queue = client.post('/queue/').json['tasks'][0]
    assert queue['type'] == 'Email' and queue['target'] == 'Verifica account ✅'
    summary = client.get(f'/api/v1/tasks/{task}/summary').json
    assert summary['type'] == 'email' and summary['authentication']['spf'] == 'fail'
    original = client.get(f'/report/{task}/original')
    assert original.status_code == 200 and 'attachment' in original.headers['Content-Disposition']
    assert original.mimetype == 'application/octet-stream'
    for path in ('', '/message', '/original', '/iocs.csv', '/json'):
        assert logged_in(web, bob).get(f'/report/{task}{path}').status_code == 404


def test_ioc_csv_neutralizes_formulas(env, tmp_path):
    web, db, alice, _, _ = env
    task = stored_email_task(web, db, alice, tmp_path)
    from shared.mongodbconn import add_item_fs
    db.fs.files.delete_many({'task': task, 'contentType': 'application/json'})
    add_item_fs('urlsandbox', 'reports', json.dumps({'iocs': {'emails': ['=HYPERLINK("x")']}}).encode(),
                'email.json', {}, task, 'application/json', datetime.utcnow())
    body = logged_in(web, alice).get(f'/report/{task}/iocs.csv').get_data(as_text=True)
    assert 'emails,"\'=HYPERLINK(""x"")"' in body


def test_link_analysis_is_attached_to_its_email_only_for_the_owner(env, tmp_path):
    web, db, alice, bob, dispatched = env
    task = stored_email_task(web, db, alice, tmp_path)
    form = {'buffer': 'https://paypa1-secure.xyz/login', 'choices': ['use_proxy'], 'useragents': 'Chrome',
            'urltimeout': '10', 'analyzertimeout': '60', 'interactivetimeout': '300', 'parent_task': task,
            'submitandwait': 'Analyze & Wait'}
    assert logged_in(web, alice).post('/url/', data=form).status_code == 302
    assert logged_in(web, bob).post('/url/', data=form).status_code == 302
    children = {doc['owner_id']: doc for doc in db.taskdblogs.find({'buffer': 'https://paypa1-secure.xyz/login'})}
    assert children[str(alice.id)]['parent_task'] == task
    assert 'parent_task' not in children[str(bob.id)]
    page = logged_in(web, alice).get('/report/' + task).get_data(as_text=True)
    assert '/report/' + children[str(alice.id)]['task'] in page


def test_worker_runs_mailbox_without_network_and_stores_report(env, tmp_path):
    from shared.logger import setup_task_logger, cancel_task_logger, log_string, ignore_exception
    from backend.qbmailreport import make_email_report
    web, db, alice, _, _ = env
    task = str(uuid4())
    (tmp_path / task).mkdir()
    (tmp_path / task / 'input.eml').write_bytes(phishing_message())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'status': 'queued', 'type': 'email',
                              'start': datetime.utcnow(), 'end': None, 'logs': []})
    launched = []

    class Container:
        def wait(self, timeout):
            launched[-1]['timeout'] = timeout
        def logs(self):
            return b'Parsed\nDone!!'
        def remove(self, force=False):
            launched[-1]['removed'] = force

    def run(image, **kwargs):
        launched.append(dict(kwargs, image=image))
        analysis, rendered = qbmail.analyze(phishing_message(), kwargs['command'][1])
        out = tmp_path / task / 'mail'
        (out / 'email.json').write_text(json.dumps(analysis))
        (out / 'message.html').write_text(rendered)
        return Container()

    def missing(name):
        raise KeyError(name)

    docker = SimpleNamespace(containers=SimpleNamespace(get=missing, run=run),
                             volumes=SimpleNamespace(get=lambda name: SimpleNamespace(attrs={'Mountpoint': '/host/artifacts'})))
    owners = []
    namespace = dict(setup_task_logger=setup_task_logger, cancel_task_logger=cancel_task_logger, log_string=log_string,
                     ignore_exception=ignore_exception, DOCKER_CLIENT=docker, json_settings=web.json_settings,
                     environ={'project_env': 'docker'}, path=os.path, makedirs=os.makedirs, UUID=UUID,
                     chmod=os.chmod, chown=lambda *args: owners.append(args), make_email_report=make_email_report,
                     EMAIL_WORKER=web.json_settings['docker']['email_worker'],
                     EMAIL_INPUTS=('input.eml', 'input.msg'), MAILBOX_USER=65534)
    source = ast.parse((ROOT / 'backend/worker.py').read_text())
    node = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'analyze_email')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'worker', 'exec'), namespace)
    with pytest.raises(ValueError):
        namespace['analyze_email'](None, {'task': task, 'owner_id': str(alice.id), 'input_name': '../x'})
    namespace['analyze_email'](None, {'task': task, 'owner_id': str(alice.id), 'input_name': 'input.eml',
                                      'filename': 'phish.eml'})
    launch = launched[0]
    assert launch['image'] == 'url-sandbox-mailbox'
    assert launch['network_mode'] == 'none' and launch['read_only'] is True
    assert launch['cap_drop'] == ['ALL'] and 'no-new-privileges' in launch['security_opt']
    assert launch['volumes'] == {
        f'/host/artifacts/{task}/input.eml': {'bind': '/in/input.eml', 'mode': 'ro'},
        f'/host/artifacts/{task}/mail': {'bind': '/out', 'mode': 'rw'}}
    assert launch['removed'] is True and owners[0][1:] == (65534, 65534)
    doc = db.taskdblogs.find_one({'task': task})
    assert doc['status'] == 'completed' and doc['verdict'] == 'suspicious'
    assert web.load_email_analysis(task)['filename'] == 'phish.eml'


def test_mailbox_entry_point_reads_only_its_input(tmp_path, monkeypatch):
    import runpy
    run = runpy.run_path(str(ROOT / 'mailbox/run.py'), run_name='mailbox_run')
    main = run['main']
    (tmp_path / 'in').mkdir()
    (tmp_path / 'out').mkdir()
    (tmp_path / 'in' / 'input.eml').write_bytes(phishing_message())
    main.__globals__.update(INPUT_DIR=str(tmp_path / 'in'), OUTPUT_DIR=str(tmp_path / 'out'))
    assert main(['../in/input.eml']) == 1 and main(['missing.eml']) == 1
    assert main(['input.eml', 'Fattura ottobre.eml']) == 0
    analysis = json.loads((tmp_path / 'out' / 'email.json').read_text())
    assert analysis['filename'] == 'Fattura ottobre.eml' and analysis['format'] == 'eml'
    assert (tmp_path / 'out' / 'message.html').read_text().startswith('<!DOCTYPE html>')
