'''
    mailbox -> attachment inspection
    Static analysis of attachments: nothing is executed. Office macros and embedded objects
    (oletools), PDF actions and links (pypdf, pdftoppm preview), archives and disk images
    (zipfile / tarfile / 7-Zip, recursive, bounded), LNK targets, OneNote embedded files,
    PE metadata, HTML smuggling / local phishing pages, QR codes and YARA rules.
'''

import re
import shutil
import subprocess
import tarfile
import zipfile
from base64 import b64decode, b64encode
from gzip import GzipFile
from hashlib import md5, sha1, sha256
from io import BytesIO
from os import path, walk, makedirs
from tempfile import TemporaryDirectory

MAX_DEPTH = 3
MAX_FILES = 300
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RATIO = 200          # uncompressed / compressed, above this an archive is treated as a bomb
TOOL_TIMEOUT = 30
MAX_MACRO_CHARS = 200 * 1024
MAX_URLS = 300
PREVIEW_MAX_BYTES = 400 * 1024

COMMON_PASSWORDS = ['infected', 'malware', 'virus', 'password', 'Password', '1234', '12345', '123456', '2024', '2025', '2026']
PASSWORD_IN_TEXT = re.compile(
    r'''(?i)(?:password|passwort|kennwort|pass|pwd|parola\s+chiave|mot\s+de\s+passe|contrase(?:ñ|n)a|senha|code)'''
    r'''\s*(?:is|è|e|:|=|-)?\s*[:=]?\s*["'«“]?([^\s"'»”<>]{3,32})''')
URL_PATTERN = re.compile(r'''(?i)\b(?:https?|ftp)://[^\s"'<>()\\]{4,2048}''')
URL_BYTES = re.compile(rb'''(?i)\b(?:https?|ftp)://[^\s"'<>()\\\x00-\x1f]{4,2048}''')
PS_ENCODED = re.compile(r'(?i)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})')
LOLBINS = re.compile(r'(?i)\b(powershell|pwsh|cmd(?:\.exe)?\s*/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|'
                     r'curl(?:\.exe)?|wget|msiexec|forfiles|conhost|schtasks|explorer\.exe\s+https?)\b')
ONENOTE_FILE_GUID = bytes.fromhex('e716e3bd65261145a4c48d4d0b7a9eac')
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

PDF_KEYWORDS = ('/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/URI', '/AcroForm', '/XFA',
                '/SubmitForm', '/RichMedia', '/ObjStm', '/Encrypt')
PDF_NAME = re.compile(rb'/[A-Za-z0-9#]{2,40}')
SUSPICIOUS_IMPORTS = {'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection',
                      'URLDownloadToFileA', 'URLDownloadToFileW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW',
                      'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'IsDebuggerPresent',
                      'SetWindowsHookExA', 'SetWindowsHookExW', 'CryptEncrypt', 'GetAsyncKeyState'}
HTML_SMUGGLING = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in (
    ('atob()', r'\batob\s*\('), ('new Blob()', r'new\s+Blob\s*\('), ('createObjectURL', r'createObjectURL'),
    ('msSaveOrOpenBlob', r'msSaveOrOpenBlob'), ('download', r'\.download\s*='), ('Uint8Array', r'Uint8Array'))]
HTML_OBFUSCATION = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in (
    ('eval()', r'\beval\s*\('), ('unescape()', r'\bunescape\s*\('), ('document.write()', r'document\.write\s*\('),
    ('String.fromCharCode', r'String\.fromCharCode'), ('Function()', r'\bFunction\s*\(\s*["\']'))]
EXFIL_PATTERN = re.compile(r'(?i)api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|/submit\.php|/post\.php|'
                           r'/next\.php|/login\.php|formspree\.io|getform\.io|script\.google\.com/macros')


def sevenzip():
    return shutil.which('7zz') or shutil.which('7z')


class Context:
    '''state shared by one message's recursive inspection: limits, passwords, rules'''

    def __init__(self, passwords=(), rules=None, rendered=None, samples=None, render=None):
        self.files = 0
        self.total = 0
        self.passwords = list(dict.fromkeys(list(passwords) + COMMON_PASSWORDS))
        self.body_passwords = set(passwords)
        self.rules = rules
        self.rendered = rendered if rendered is not None else {}
        self.samples = samples if samples is not None else {}
        self.render = render
        self.notes = []

    def admit(self, size):
        if self.files >= MAX_FILES or self.total + size > MAX_TOTAL_BYTES:
            return False
        self.files += 1
        self.total += size
        return True


def passwords_in(text):
    found = []
    for match in PASSWORD_IN_TEXT.finditer(text or ''):
        word = match.group(1).strip('.,;:!?)')
        if 3 <= len(word) <= 32 and word.lower() not in ('the', 'and', 'per', 'il', 'la', 'your', 'this', 'reset'):
            found.append(word)
    return list(dict.fromkeys(found))[:10]


def hashes(data):
    return {'md5': md5(data).hexdigest(), 'sha1': sha1(data).hexdigest(), 'sha256': sha256(data).hexdigest()}


def urls_in_text(text):
    return [url.rstrip('.,;:!?\'"') for url in URL_PATTERN.findall(text or '')]


def urls_in_bytes(data):
    found = [url.decode('latin-1').rstrip('.,;:!?\'"') for url in URL_BYTES.findall(data)]
    try:
        found += urls_in_text(data.decode('utf-16-le', 'ignore'))
    except Exception:
        pass
    return found


class Result:
    '''what one file produced; children are Results too'''

    def __init__(self):
        self.findings = []      # {'tool', 'title', 'detail', 'severity'}
        self.indicators = []    # (indicator id, detail)
        self.urls = []          # (url, where)
        self.macros = []
        self.macro_keywords = []
        self.children = []
        self.preview = None
        self.rendered = False
        self.qr = []
        self.yara = []
        self.lnk = None
        self.pe = None
        self.pdf = None
        self.archive = None

    def finding(self, tool, title, detail='', severity='info'):
        self.findings.append({'tool': tool, 'title': title, 'detail': str(detail)[:2000], 'severity': severity})

    def indicator(self, key, detail=''):
        self.indicators.append((key, detail))

    def url(self, url, where):
        if len(self.urls) < MAX_URLS:
            self.urls.append((url, where))

    def as_dict(self):
        return {'findings': self.findings, 'macros': self.macros, 'macro_keywords': self.macro_keywords,
                'children': self.children, 'preview': self.preview,
                'rendered': self.rendered, 'qr': self.qr, 'yara': self.yara, 'lnk': self.lnk, 'pe': self.pe,
                'pdf': self.pdf, 'archive': self.archive,
                'urls': [{'url': url, 'where': where} for url, where in self.urls],
                'indicators': [{'id': key, 'detail': detail} for key, detail in self.indicators]}


# ---------------------------------------------------------------- dispatcher


def inspect(data, name, family, ctx, depth=0, chain=''):
    '''analyze one file; returns a Result. family is the content type from qbmail.detect_type'''
    result = Result()
    where = chain + name if chain else name
    analyzers = []
    lower = (name or '').lower()
    if family == 'ooxml':
        analyzers += [office_vba, ooxml_relations, ooxml_embedded, office_dde]
    if family == 'ole' and not lower.endswith('.msg'):
        analyzers += [office_encrypted, office_vba, ole_embedded, office_dde]
    if family == 'rtf':
        analyzers += [rtf_objects]
    if family == 'pdf':
        analyzers += [pdf_analysis]
    if family in ('zip', 'rar', '7z', 'gzip', 'cab', 'iso') and depth < MAX_DEPTH:
        analyzers += [archive_analysis]
    elif family == 'data' and lower.endswith(('.img', '.vhd', '.vhdx', '.tar', '.ace', '.arj', '.lzh', '.xz', '.bz2')) \
            and depth < MAX_DEPTH:
        analyzers += [archive_analysis]
    if family == 'lnk' or lower.endswith('.lnk'):
        analyzers += [lnk_analysis]
    if lower.endswith(('.one', '.onepkg')) and depth < MAX_DEPTH:
        analyzers += [onenote_analysis]
    if family == 'pe':
        analyzers += [pe_analysis]
    if family in ('html', 'svg') or lower.endswith(('.html', '.htm', '.shtml', '.xhtml', '.svg', '.hta')):
        analyzers += [html_analysis]
    if family in ('png', 'jpeg', 'gif'):
        analyzers += [qr_image]
    if lower.endswith(('.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.ps1', '.bat', '.cmd')):
        analyzers += [script_analysis]
    for analyzer in analyzers:
        if analyzer is office_dde and any(key == 'encrypted_document' for key, _ in result.indicators):
            continue
        try:
            analyzer(data, name, result, ctx, depth, where)
        except Exception as error:  # a malformed file must not stop the rest of the analysis
            result.finding(analyzer.__name__, 'Analysis failed', '{}: {}'.format(type(error).__name__, error))
    yara_scan(data, result, ctx)
    return result


def add_child(data, name, result, ctx, depth, where, how):
    '''inspect an extracted file and attach it to its parent'''
    from qbmail import detect_type, attachment_flags
    if not ctx.admit(len(data)):
        ctx.notes.append('limit reached: {} not inspected'.format(name))
        result.finding('limits', 'File not inspected', '{} ({}): file or size limit reached'.format(name, how))
        return
    family, label = detect_type(data)
    flags = attachment_flags(name, data, family)
    child = inspect(data, name, family, ctx, depth + 1, where + ' › ')
    digest = hashes(data)
    ctx.samples.setdefault(digest['sha256'], (name, data))
    result.children.append({'filename': name, 'size': len(data), 'detected': family, 'detected_label': label,
                            'flags': flags, 'via': how, **digest, 'analysis': child.as_dict()})
    for key, detail in child.indicators:
        result.indicator(key, detail)
    for flag, key in (('executable', 'executable_attachment'), ('macro_enabled', 'macro_attachment'),
                      ('contains_macros', 'macro_attachment'), ('html', 'html_attachment'),
                      ('disk_image', 'disk_image_attachment'), ('onenote', 'onenote_attachment'),
                      ('double_extension', 'double_extension'), ('rtlo_filename', 'rtlo_filename')):
        if flag in flags:
            result.indicator(key, where + ' › ' + name)
    result.urls.extend(child.urls[:MAX_URLS])
    result.qr.extend(child.qr)


# ---------------------------------------------------------------- Office


def office_vba(data, name, result, ctx, depth, where):
    from oletools.olevba import VBA_Parser
    parser = VBA_Parser(name or 'document', data=data)
    try:
        if not parser.detect_vba_macros():
            if parser.detect_xlm_macros():
                result.finding('olevba', 'Excel 4.0 (XLM) macros',
                               '\n'.join(str(line) for line in (parser.xlm_macros or [])[:50]), 'high')
                result.indicator('macro_suspicious', where + ': Excel 4.0 macros')
            return
        code_parts = []
        for _, stream, vba_name, code in parser.extract_macros():
            text = code if isinstance(code, str) else code.decode('latin-1', 'replace')
            if not text.strip():
                continue
            code_parts.append(text)
            result.macros.append({'stream': str(stream), 'module': str(vba_name),
                                  'code': text[:MAX_MACRO_CHARS], 'truncated': len(text) > MAX_MACRO_CHARS})
        keywords = []
        for kind, keyword, description in parser.analyze_macros():
            keywords.append({'type': kind, 'keyword': str(keyword)[:300], 'description': str(description)[:300]})
            if kind == 'IOC' and URL_PATTERN.match(str(keyword)):
                result.url(str(keyword), where + ' (macro)')
        result.macro_keywords = keywords[:300]
        autoexec = [k['keyword'] for k in keywords if k['type'] == 'AutoExec']
        suspicious = [k['keyword'] for k in keywords if k['type'] == 'Suspicious']
        result.finding('olevba', '{} VBA module{}'.format(len(result.macros), '' if len(result.macros) == 1 else 's'),
                       'auto-exec: {} · suspicious: {}'.format(', '.join(autoexec[:8]) or '—', ', '.join(suspicious[:12]) or '—'),
                       'high' if autoexec and suspicious else 'medium')
        try:
            if parser.detect_vba_stomping():
                result.finding('olevba', 'VBA stomping', 'The VBA source does not match the compiled p-code: the real code is hidden.', 'high')
                result.indicator('vba_stomping', where)
        except Exception:
            pass
        from oletools.mraptor import MacroRaptor
        raptor = MacroRaptor('\n'.join(code_parts))
        raptor.scan()
        flags = ''.join(letter for letter, on in (('A', raptor.autoexec), ('W', raptor.write), ('X', raptor.execute)) if on)
        result.finding('mraptor', 'Macro classified as {}'.format('SUSPICIOUS' if raptor.suspicious else 'not suspicious'),
                       'flags: {} (A = runs on open, W = writes files, X = executes)'.format(flags or 'none'),
                       'high' if raptor.suspicious else 'low')
        if autoexec:
            result.indicator('macro_autoexec', where)
        if raptor.suspicious:
            result.indicator('macro_suspicious', '{} [{}]'.format(where, flags))
        for text in code_parts:
            for url in urls_in_text(text):
                result.url(url, where + ' (macro)')
    finally:
        parser.close()


def ooxml_relations(data, name, result, ctx, depth, where):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        for entry in archive.namelist():
            if not entry.endswith('.rels'):
                continue
            text = archive.read(entry)[:2 * 1024 * 1024].decode('utf-8', 'replace')
            for relation in re.finditer(r'<Relationship\b[^>]*>', text):
                tag = relation.group(0)
                if 'TargetMode="External"' not in tag:
                    continue
                target = re.search(r'Target="([^"]*)"', tag)
                kind = re.search(r'Type="[^"]*/([^"/]+)"', tag)
                target = target.group(1).replace('&amp;', '&') if target else ''
                kind = kind.group(1) if kind else ''
                if kind in ('attachedTemplate', 'oleObject', 'frame', 'subDocument'):
                    result.finding('oleobj', 'Remote {} loaded on open'.format(kind), target, 'high')
                    result.indicator('remote_template', '{}: {}'.format(where, target[:200]))
                if target.lower().startswith(('http://', 'https://', 'ftp://')):
                    result.url(target, '{} ({})'.format(where, kind or 'relationship'))
                elif target.lower().startswith(('file://', '\\\\')):
                    result.finding('oleobj', 'External UNC/file target ({})'.format(kind), target, 'high')
                    result.indicator('remote_template', '{}: {}'.format(where, target[:200]))


def ooxml_embedded(data, name, result, ctx, depth, where):
    if depth >= MAX_DEPTH:
        return
    with zipfile.ZipFile(BytesIO(data)) as archive:
        for info in archive.infolist():
            if '/embeddings/' not in info.filename or info.file_size > MAX_FILE_BYTES:
                continue
            payload = archive.read(info)
            if payload.startswith(OLE_MAGIC):
                packaged = ole_native(payload)
                if packaged:
                    add_child(packaged[1], packaged[0], result, ctx, depth, where, 'embedded OLE package')
                    continue
            add_child(payload, path.basename(info.filename), result, ctx, depth, where, 'embedded object')


def ole_native(payload):
    '''(filename, data) of an OLE "Package" object, if the compound file holds one'''
    import olefile
    from oletools.oleobj import OleNativeStream
    with olefile.OleFileIO(payload) as ole:
        for entry in ole.listdir():
            if entry[-1] == '\x01Ole10Native':
                native = OleNativeStream(ole.openstream(entry).read())
                return (native.filename or 'package.bin'), bytes(native.data or b'')
    return None


def ole_embedded(data, name, result, ctx, depth, where):
    import olefile
    from oletools.oleobj import OleNativeStream
    if depth >= MAX_DEPTH:
        return
    with olefile.OleFileIO(data) as ole:
        for entry in ole.listdir():
            if entry[-1] == '\x01Ole10Native':
                native = OleNativeStream(ole.openstream(entry).read())
                add_child(bytes(native.data or b''), native.filename or 'package.bin', result, ctx, depth, where,
                          'OLE package ({})'.format('/'.join(entry[:-1]) or 'root'))


def office_encrypted(data, name, result, ctx, depth, where):
    import olefile
    with olefile.OleFileIO(data) as ole:
        if ole.exists('EncryptionInfo') or ole.exists('EncryptedPackage'):
            result.finding('oleid', 'Encrypted Office document', 'Content cannot be inspected without the password.', 'medium')
            result.indicator('encrypted_document', where)


def office_dde(data, name, result, ctx, depth, where):
    from oletools import msodde
    with TemporaryDirectory() as folder:
        target = path.join(folder, path.basename(name or 'document') or 'document')
        with open(target, 'wb') as handle:
            handle.write(data)
        found = msodde.process_maybe_encrypted(target, field_filter_mode=msodde.FIELD_FILTER_BLACKLIST) or ''
    found = found.strip()
    if found:
        result.finding('msodde', 'DDE field', found, 'high')
        result.indicator('dde_field', '{}: {}'.format(where, found[:200]))
        for url in urls_in_text(found):
            result.url(url, where + ' (DDE)')


def rtf_objects(data, name, result, ctx, depth, where):
    from oletools.rtfobj import RtfObjParser
    parser = RtfObjParser(data)
    parser.parse()
    for index, item in enumerate(parser.objects):
        if not item.is_ole:
            continue
        class_name = (item.class_name or b'').decode('latin-1', 'replace') if isinstance(item.class_name, bytes) else str(item.class_name or '')
        detail = class_name + (' — ' + item.clsid_desc if getattr(item, 'clsid_desc', None) else '')
        severity = 'medium'
        if 'equation' in class_name.lower() or 'equation' in str(getattr(item, 'clsid_desc', '')).lower():
            severity = 'high'
            result.indicator('equation_editor', where)
        result.finding('rtfobj', 'Embedded OLE object #{}'.format(index), detail, severity)
        if item.is_package and depth < MAX_DEPTH:
            add_child(bytes(item.olepkgdata or b''), item.filename or 'object{}.bin'.format(index), result, ctx, depth,
                      where, 'RTF OLE package')
        elif item.oledata and depth < MAX_DEPTH:
            add_child(bytes(item.oledata), 'object{}.ole'.format(index), result, ctx, depth, where, 'RTF OLE object')


# ---------------------------------------------------------------- PDF


def pdf_names(data):
    counts = {}
    for raw in PDF_NAME.findall(data):
        # names can hide behind #xx escapes (/J#61vaScript)
        name = re.sub(rb'#([0-9a-fA-F]{2})', lambda m: bytes([int(m.group(1), 16)]), raw).decode('latin-1')
        if name in PDF_KEYWORDS:
            counts[name] = counts.get(name, 0) + 1
    return counts


def pdf_string(raw):
    '''decode a PDF literal string: \\ddd octal, \\n-style and escaped delimiters'''
    escapes = {b'n': b'\n', b'r': b'\r', b't': b'\t', b'b': b'\b', b'f': b'\f'}

    def replace(match):
        token = match.group(1)
        if token[:1].isdigit():
            return bytes([int(token, 8) & 0xff])
        return escapes.get(token, token)
    return re.sub(rb'\\([0-7]{1,3}|.)', replace, raw, flags=re.DOTALL).decode('latin-1')


def pdf_analysis(data, name, result, ctx, depth, where):
    counts = pdf_names(data)
    result.pdf = {'keywords': counts}
    if counts.get('/JavaScript') or counts.get('/JS'):
        result.finding('pdfid', 'JavaScript', '{} occurrence(s)'.format(counts.get('/JavaScript', 0) + counts.get('/JS', 0)), 'high')
        result.indicator('pdf_javascript', where)
    if counts.get('/Launch'):
        result.finding('pdfid', 'Launch action', 'The PDF can start a program.', 'high')
        result.indicator('pdf_launch', where)
    if counts.get('/OpenAction') or counts.get('/AA'):
        result.finding('pdfid', 'Automatic action on open', '/OpenAction or /AA present', 'medium')
    if counts.get('/XFA') or counts.get('/SubmitForm'):
        result.finding('pdfid', 'Form that submits data', '/XFA or /SubmitForm present', 'medium')
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(data), strict=False)
    if reader.is_encrypted:
        try:
            reader.decrypt('')
        except Exception:
            result.finding('pypdf', 'Encrypted PDF', 'Content cannot be inspected without the password.', 'medium')
            return
    result.pdf['pages'] = len(reader.pages)
    seen = set()
    for number, page in enumerate(reader.pages[:200]):
        for annotation in page.get('/Annots') or []:
            try:
                action = annotation.get_object().get('/A') or {}
                uri = action.get_object().get('/URI') if hasattr(action, 'get_object') else action.get('/URI')
            except Exception:
                uri = None
            if uri and str(uri) not in seen:
                seen.add(str(uri))
                result.url(str(uri), '{} (page {})'.format(where, number + 1))
    for uri in re.findall(rb'/URI\s*\(((?:[^)\\]|\\.){4,2048})\)', data):
        text = pdf_string(uri)
        if text not in seen:
            seen.add(text)
            result.url(text, where)
    if seen:
        result.finding('pypdf', '{} clickable link{}'.format(len(seen), '' if len(seen) == 1 else 's'), ', '.join(list(seen)[:5]))
    try:
        attachments = reader.attachments
    except Exception:
        attachments = {}
    if attachments:
        result.finding('pypdf', 'Embedded files', ', '.join(attachments)[:500], 'high')
        result.indicator('pdf_embedded_file', where)
        if depth < MAX_DEPTH:
            for filename, payloads in attachments.items():
                for payload in payloads[:5]:
                    add_child(bytes(payload), filename, result, ctx, depth, where, 'PDF embedded file')
    pdf_preview(data, result, where)


def pdf_preview(data, result, where):
    '''first page as an image (shown in the report and scanned for QR codes)'''
    if not shutil.which('pdftoppm'):
        return
    with TemporaryDirectory() as folder:
        source = path.join(folder, 'in.pdf')
        with open(source, 'wb') as handle:
            handle.write(data)
        subprocess.run(['pdftoppm', '-png', '-r', '110', '-f', '1', '-l', '1', '-singlefile', source,
                        path.join(folder, 'page')], timeout=TOOL_TIMEOUT, capture_output=True, check=False)
        page = path.join(folder, 'page.png')
        if not path.exists(page):
            return
        with open(page, 'rb') as handle:
            image = handle.read()
    for text in decode_qr(image):
        result.qr.append({'where': where + ' (page 1)', 'text': text})
        if URL_PATTERN.match(text):
            result.url(text, where + ' (QR code)')
            result.indicator('qr_code_url', '{}: {}'.format(where, text[:200]))
    result.preview = thumbnail(image)


def thumbnail(image, width=520):
    try:
        from PIL import Image
        picture = Image.open(BytesIO(image)).convert('RGB')
        picture.thumbnail((width, width * 2))
        output = BytesIO()
        picture.save(output, format='PNG', optimize=True)
        payload = output.getvalue()
        if len(payload) <= PREVIEW_MAX_BYTES:
            return 'data:image/png;base64,' + b64encode(payload).decode()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- archives


def archive_analysis(data, name, result, ctx, depth, where):
    lower = (name or '').lower()
    if data[:4] == b'PK\x03\x04':
        entries = zip_entries(data, result, ctx, where)
    elif data[:2] == b'\x1f\x8b' and not lower.endswith(('.tgz', '.tar.gz')):
        entries = gzip_entries(data, name, result)
    elif lower.endswith(('.tar', '.tgz', '.tar.gz')):
        entries = tar_entries(data, result)
    else:
        entries = sevenzip_entries(data, name, result, ctx, where)
    for entry_name, payload in entries:
        add_child(payload, entry_name, result, ctx, depth, where, 'archive member')


def check_bomb(result, compressed, uncompressed, count):
    if count > MAX_FILES or uncompressed > MAX_TOTAL_BYTES or (compressed and uncompressed / max(compressed, 1) > MAX_RATIO
                                                                and uncompressed > 10 * 1024 * 1024):
        result.finding('archive', 'Not extracted: possible decompression bomb',
                       '{} files, {} bytes uncompressed from {} bytes'.format(count, uncompressed, compressed), 'high')
        result.indicator('archive_bomb', '')
        return True
    return False


def note_password(result, ctx, password, where):
    result.archive = dict(result.archive or {}, encrypted=True, password=password)
    if password is None:
        result.finding('archive', 'Password-protected', 'No known password opened it.', 'high')
        return
    result.finding('archive', 'Opened with password', password, 'high')
    if password in ctx.body_passwords:
        result.indicator('archive_password_in_body', '{} (password "{}")'.format(where, password))


def zip_entries(data, result, ctx, where):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        result.archive = {'type': 'zip', 'entries': [{'name': info.filename, 'size': info.file_size} for info in infos[:200]]}
        if check_bomb(result, len(data), sum(info.file_size for info in infos), len(infos)):
            return []
        encrypted = any(info.flag_bits & 0x1 for info in infos)
        aes = any(info.compress_type == 99 for info in infos)
        if aes and sevenzip():
            return sevenzip_entries(data, 'archive.zip', result, ctx, where)
        password = None
        if encrypted:
            for candidate in ctx.passwords:
                try:
                    archive.read(infos[0], pwd=candidate.encode())
                    password = candidate
                    break
                except Exception:
                    continue
            note_password(result, ctx, password, where)
            if password is None:
                return []
        entries = []
        for info in infos:
            if info.file_size > MAX_FILE_BYTES:
                continue
            entries.append((path.basename(info.filename) or info.filename,
                            archive.read(info, pwd=password.encode() if password else None)))
        return entries


def gzip_entries(data, name, result):
    with GzipFile(fileobj=BytesIO(data)) as handle:
        payload = handle.read(MAX_FILE_BYTES + 1)
    if len(payload) > MAX_FILE_BYTES:
        check_bomb(result, len(data), MAX_TOTAL_BYTES + 1, 1)
        return []
    if payload[257:262] == b'ustar':
        return tar_entries(payload, result)
    inner = (name or 'file.gz')[:-3] if (name or '').lower().endswith('.gz') else (name or 'file') + '.out'
    result.archive = {'type': 'gzip', 'entries': [{'name': inner, 'size': len(payload)}]}
    return [(inner, payload)]


def tar_entries(data, result):
    with tarfile.open(fileobj=BytesIO(data)) as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        result.archive = {'type': 'tar', 'entries': [{'name': m.name, 'size': m.size} for m in members[:200]]}
        if check_bomb(result, len(data), sum(m.size for m in members), len(members)):
            return []
        return [(path.basename(m.name), archive.extractfile(m).read()) for m in members if m.size <= MAX_FILE_BYTES]


def sevenzip_entries(data, name, result, ctx, where):
    binary = sevenzip()
    if not binary:
        result.finding('7-Zip', 'Not inspected', '7-Zip is not available in this image.')
        return []
    with TemporaryDirectory() as folder:
        source = path.join(folder, 'input.bin')
        with open(source, 'wb') as handle:
            handle.write(data)

        def listing(password):
            run = subprocess.run([binary, 'l', '-slt', '-p' + password, source], capture_output=True,
                                 timeout=TOOL_TIMEOUT, check=False)
            return run.returncode, run.stdout.decode('utf-8', 'replace')

        code, text = listing('')
        blocks = text.split('----------', 1)[-1].split('\n\n')
        entries = []
        for block in blocks:
            fields = dict(line.split(' = ', 1) for line in block.splitlines() if ' = ' in line)
            if 'Path' in fields and fields.get('Folder') != '+' and 'Size' in fields:
                entries.append({'name': fields['Path'], 'size': int(fields.get('Size') or 0),
                                'encrypted': fields.get('Encrypted') == '+'})
        archive_type = re.search(r'^Type = (\S+)', text, re.MULTILINE)
        result.archive = {'type': archive_type.group(1) if archive_type else 'archive',
                          'entries': [{'name': e['name'], 'size': e['size']} for e in entries[:200]]}
        if code != 0 and not entries:
            result.finding('7-Zip', 'Could not open', text.strip().splitlines()[-1] if text.strip() else 'unknown format')
            return []
        if check_bomb(result, len(data), sum(e['size'] for e in entries), len(entries)):
            return []
        password = ''
        if any(e['encrypted'] for e in entries) or 'Wrong password' in text:
            password = None
            for candidate in ctx.passwords:
                test = subprocess.run([binary, 't', '-p' + candidate, source], capture_output=True,
                                      timeout=TOOL_TIMEOUT, check=False)
                if test.returncode == 0:
                    password = candidate
                    break
            note_password(result, ctx, password, where)
            if password is None:
                return []
        out = path.join(folder, 'out')
        makedirs(out)
        subprocess.run([binary, 'x', '-y', '-snl-', '-p' + password, '-o' + out, source], capture_output=True,
                       timeout=TOOL_TIMEOUT, check=False)
        extracted = []
        for root, _, files in walk(out):
            for filename in files:
                full = path.join(root, filename)
                if path.islink(full) or path.getsize(full) > MAX_FILE_BYTES:
                    continue
                with open(full, 'rb') as handle:
                    extracted.append((filename, handle.read()))
        return extracted


# ---------------------------------------------------------------- LNK, OneNote, PE


def decode_powershell(arguments):
    decoded = []
    for blob in PS_ENCODED.findall(arguments or ''):
        try:
            decoded.append(b64decode(blob + '=' * (-len(blob) % 4)).decode('utf-16-le', 'replace'))
        except Exception:
            continue
    return decoded


def lnk_analysis(data, name, result, ctx, depth, where):
    import LnkParse3
    info = LnkParse3.lnk_file(BytesIO(data)).get_json()
    strings = info.get('data') or {}
    link = info.get('link_info') or {}
    target = link.get('local_base_path') or strings.get('relative_path') or ''
    arguments = strings.get('command_line_arguments') or ''
    result.lnk = {'target': target, 'arguments': arguments[:4000], 'working_directory': strings.get('working_directory') or '',
                  'icon': strings.get('icon_location') or '', 'decoded': [text[:4000] for text in decode_powershell(arguments)]}
    command = '{} {}'.format(target, arguments).strip()
    severity = 'high' if LOLBINS.search(command) else 'medium'
    result.finding('LnkParse3', 'Shortcut runs a command', command[:1000], severity)
    if severity == 'high':
        result.indicator('lnk_command', '{}: {}'.format(where, command[:200]))
    for text in [command] + result.lnk['decoded']:
        for url in urls_in_text(text):
            result.url(url, where + ' (LNK)')


def onenote_analysis(data, name, result, ctx, depth, where):
    from struct import unpack_from
    offset, count = 0, 0
    while True:
        offset = data.find(ONENOTE_FILE_GUID, offset)
        if offset < 0 or offset + 36 > len(data):
            break
        size = unpack_from('<Q', data, offset + 16)[0]
        start = offset + 36
        if 0 < size <= MAX_FILE_BYTES and start + size <= len(data):
            count += 1
            add_child(data[start:start + size], 'embedded{}.bin'.format(count), result, ctx, depth, where,
                      'OneNote embedded file')
        offset = start
    result.finding('onenote', '{} embedded file{}'.format(count, '' if count == 1 else 's'), '', 'high' if count else 'info')


def pe_analysis(data, name, result, ctx, depth, where):
    import pefile
    from datetime import datetime, timezone
    pe = pefile.PE(data=data, fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                               pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        imports = sorted({entry.name.decode('latin-1') for library in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                          for entry in library.imports if entry.name})
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        sections = [{'name': section.Name.rstrip(b'\0').decode('latin-1'), 'entropy': round(section.get_entropy(), 2),
                     'size': section.SizeOfRawData} for section in pe.sections]
        result.pe = {
            'imphash': pe.get_imphash() if imports else '',
            'compiled': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            'machine': hex(pe.FILE_HEADER.Machine), 'dll': pe.is_dll(), 'signed': security.Size > 0,
            'sections': sections, 'suspicious_imports': sorted(SUSPICIOUS_IMPORTS.intersection(imports)),
            'imports': len(imports),
        }
        packed = [s['name'] for s in sections if s['entropy'] > 7.2]
        result.finding('pefile', 'Windows {}'.format('DLL' if result.pe['dll'] else 'executable'),
                       'imphash {} · compiled {} · {}'.format(result.pe['imphash'] or '—', result.pe['compiled'],
                                                             'signed' if result.pe['signed'] else 'not signed'),
                       'high')
        if packed:
            result.finding('pefile', 'Packed or encrypted sections', ', '.join(packed), 'medium')
        if result.pe['suspicious_imports']:
            result.finding('pefile', 'Suspicious imports', ', '.join(result.pe['suspicious_imports']), 'medium')
    finally:
        pe.close()
    for url in urls_in_bytes(data)[:50]:
        result.url(url, where + ' (strings)')


# ---------------------------------------------------------------- HTML, scripts, QR


def html_analysis(data, name, result, ctx, depth, where):
    text = data[:5 * 1024 * 1024].decode('utf-8', 'replace')
    smuggling = [label for label, pattern in HTML_SMUGGLING if pattern.search(text)]
    long_base64 = re.search(r'[A-Za-z0-9+/]{2000,}={0,2}', text) is not None
    if (len(smuggling) >= 2 and set(smuggling) & {'new Blob()', 'createObjectURL', 'msSaveOrOpenBlob', 'download'}) \
            or (long_base64 and smuggling):
        result.finding('html', 'HTML smuggling', 'builds a file in the browser: ' + ', '.join(smuggling), 'high')
        result.indicator('html_smuggling', where)
    if re.search(r'''(?i)<input[^>]+type\s*=\s*["']?password''', text):
        result.finding('html', 'Login form', 'The page asks for a password: typical local phishing page.', 'high')
        result.indicator('local_phishing_page', where)
    exfil = sorted(set(EXFIL_PATTERN.findall(text)))
    if exfil:
        result.finding('html', 'Data sent to', ', '.join(exfil), 'high')
        result.indicator('local_phishing_page', '{}: {}'.format(where, ', '.join(exfil)))
    obfuscated = [label for label, pattern in HTML_OBFUSCATION if pattern.search(text)]
    if obfuscated:
        result.finding('html', 'Obfuscated script', ', '.join(obfuscated), 'medium')
    if re.search(r'''(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh|window\.location|location\.href\s*=|location\.replace''', text):
        result.finding('html', 'Redirect', 'The page redirects the browser.', 'medium')
    if name.lower().endswith('.svg') and re.search(r'(?i)<script|on\w+\s*=|<foreignObject', text):
        result.finding('html', 'Script inside an SVG image', '', 'high')
        result.indicator('svg_script', where)
    for url in urls_in_text(text):
        result.url(url, where)
    if ctx.render is not None:
        digest = sha256(data).hexdigest()
        ctx.rendered[digest] = ctx.render(text, where)
        result.rendered = True


def script_analysis(data, name, result, ctx, depth, where):
    text = data[:2 * 1024 * 1024].decode('utf-8', 'replace')
    if '\x00' in text[:200]:
        text = data[:2 * 1024 * 1024].decode('utf-16-le', 'replace')
    hits = sorted(set(match.group(1).lower() for match in LOLBINS.finditer(text)))
    if hits:
        result.finding('script', 'Launches system tools', ', '.join(hits), 'high')
        result.indicator('script_command', '{}: {}'.format(where, ', '.join(hits)))
    for decoded in decode_powershell(text):
        result.finding('script', 'Encoded PowerShell', decoded[:1000], 'high')
        for url in urls_in_text(decoded):
            result.url(url, where + ' (decoded)')
    for url in urls_in_text(text):
        result.url(url, where)


def decode_qr(image):
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode, ZBarSymbol
    except Exception:
        return []
    picture = Image.open(BytesIO(image))
    picture.load()
    found = []
    for symbol in decode(picture.convert('L'), symbols=[ZBarSymbol.QRCODE]):
        found.append(symbol.data.decode('utf-8', 'replace'))
    return found


def qr_image(data, name, result, ctx, depth, where):
    for text in decode_qr(data):
        result.qr.append({'where': where, 'text': text})
        result.finding('pyzbar', 'QR code', text[:500], 'medium')
        if URL_PATTERN.match(text):
            result.url(text, where + ' (QR code)')
            result.indicator('qr_code_url', '{}: {}'.format(where, text[:200]))


# ---------------------------------------------------------------- YARA


def load_rules(folders):
    try:
        import yara
    except Exception:
        return None
    sources = {}
    for folder in folders:
        if not folder or not path.isdir(folder):
            continue
        for root, _, files in walk(folder):
            for filename in sorted(files):
                if filename.endswith(('.yar', '.yara')):
                    sources['{}/{}'.format(path.basename(root), filename)] = path.join(root, filename)
    if not sources:
        return None
    compiled = {}
    for namespace, filename in sources.items():
        try:
            compiled[namespace] = yara.compile(filepath=filename)
        except Exception as error:
            print('YARA rule file skipped: {} ({})'.format(namespace, error))
    return compiled or None


def yara_matches(rules, data):
    if not rules:
        return []
    found = []
    for namespace, compiled in rules.items():
        try:
            for match in compiled.match(data=data, timeout=TOOL_TIMEOUT):
                found.append({'rule': match.rule, 'namespace': namespace, 'tags': list(match.tags),
                              'description': str(match.meta.get('description', ''))[:300]})
        except Exception:
            continue
    return found


def yara_scan(data, result, ctx):
    matches = yara_matches(ctx.rules, data)
    if matches:
        result.yara = matches
        names = ', '.join(sorted({m['rule'] for m in matches}))
        result.finding('YARA', 'Rule match', names, 'high')
        result.indicator('yara_match', names)
