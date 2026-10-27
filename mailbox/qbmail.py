'''
    mailbox -> email parser and analyzer
    Parses an .eml or .msg file into one structure (headers, hops, authentication, links,
    attachments, indicators) and renders the body as a self-contained, inert HTML document
    that keeps the original layout: no scripts, no forms that submit, no remote requests.
'''

import re
from base64 import b64encode
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from hashlib import md5, sha1, sha256
from html import escape
from io import BytesIO
from ipaddress import ip_address
from urllib.parse import parse_qs, unquote, urlsplit
from zipfile import ZipFile, BadZipFile

from bs4 import BeautifulSoup, Comment

try:
    from tldextract import TLDExtract
    # The bundled public-suffix snapshot only: this runs without network.
    _EXTRACT = TLDExtract(cache_dir=None, suffix_list_urls=())
except Exception:  # pragma: no cover - tldextract is part of the image
    _EXTRACT = None

MAX_TEXT = 200 * 1024
MAX_HTML_SOURCE = 512 * 1024
MAX_PARTS = 500
MAX_LINKS = 1000

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
# 1x1 transparent GIF: blocked images keep their box so the layout does not collapse
BLANK_IMAGE = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'

EXECUTABLE_EXT = {'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta',
                  'ps1', 'psm1', 'msi', 'msp', 'lnk', 'cpl', 'jar', 'reg', 'scf', 'dll', 'chm', 'appx',
                  'msix', 'appxbundle', 'xll', 'url', 'inf', 'sct', 'application', 'gadget'}
DISK_IMAGE_EXT = {'iso', 'img', 'vhd', 'vhdx'}
MACRO_EXT = {'docm', 'dotm', 'xlsm', 'xltm', 'xlsb', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm'}
LEGACY_OFFICE_EXT = {'doc', 'dot', 'xls', 'xlt', 'ppt', 'pot', 'pps'}
HTML_EXT = {'html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml'}
ARCHIVE_EXT = {'zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'ace', 'cab', 'arj', 'bz2', 'xz', 'lzh', 'z'}
ONENOTE_EXT = {'one', 'onepkg'}

# extension -> detected family it is expected to match (mismatch is an indicator)
EXPECTED_FAMILY = {
    'pdf': 'pdf', 'rtf': 'rtf', 'zip': 'zip', 'rar': 'rar', '7z': '7z', 'gz': 'gzip', 'tgz': 'gzip',
    'png': 'png', 'tif': 'tiff', 'tiff': 'tiff', 'jpg': 'jpeg', 'jpeg': 'jpeg', 'gif': 'gif', 'exe': 'pe', 'dll': 'pe', 'scr': 'pe',
    'docx': 'ooxml', 'xlsx': 'ooxml', 'pptx': 'ooxml', **{ext: 'ooxml' for ext in MACRO_EXT - {'xlsb'}},
    'xlsb': 'ooxml', **{ext: 'ole' for ext in LEGACY_OFFICE_EXT}, 'msg': 'ole', 'html': 'html', 'htm': 'html',
    'iso': 'iso', 'cab': 'cab', 'lnk': 'lnk',
}

SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
              'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink', 'lnkd.in', 's.id', 'v.gd', 'qrco.de',
              'shorturl.gg', 'urlz.fr', 'n9.cl'}

URL_IN_TEXT = re.compile(r'''(?i)\b((?:https?://|www\.)[^\s<>"' ​]+)''')
LOOKS_LIKE_URL = re.compile(r'(?i)^(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:[/:?#]\S*)?$')
EMAIL_IN_TEXT = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
IPV6_TAG = re.compile(r'IPv6:([0-9a-fA-F:.]+)')
CSS_URL = re.compile(r'''url\(\s*(['"]?)(.*?)\1\s*\)''', re.IGNORECASE | re.DOTALL)
CSS_IMPORT = re.compile(r'@import[^;]*;?', re.IGNORECASE)
CSS_DANGEROUS = re.compile(r'expression\s*\(|behavior\s*:|-moz-binding', re.IGNORECASE)

DROP_TAGS = {'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'meta', 'link',
             'portal', 'template', 'audio', 'video', 'source', 'track'}
URL_ATTRS = {'src', 'lowsrc', 'dynsrc', 'srcset', 'background', 'poster', 'action', 'formaction', 'data',
             'codebase', 'cite', 'longdesc', 'ping', 'manifest', 'xlink:href'}


def hashes(data):
    return {'md5': md5(data).hexdigest(), 'sha1': sha1(data).hexdigest(), 'sha256': sha256(data).hexdigest()}


def clean_space(value):
    return ' '.join(str(value or '').split())


def registered_domain(host):
    host = (host or '').strip('.').lower()
    if not host:
        return ''
    if _EXTRACT is None:
        return '.'.join(host.split('.')[-2:])
    parts = _EXTRACT(host)
    if parts.domain and parts.suffix:
        return '{}.{}'.format(parts.domain, parts.suffix)
    return parts.domain or host


def address_domain(address):
    return address.rsplit('@', 1)[1].lower() if address and '@' in address else ''


def public_ip(value):
    try:
        ip = ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def mailbox(value):
    name, address = parseaddr(clean_space(value))
    return {'name': name, 'address': address.lower()}


def mailbox_list(values):
    return [{'name': name, 'address': address.lower()}
            for name, address in getaddresses([clean_space(v) for v in values if v]) if address or name]


# ---------------------------------------------------------------- parsing


def text_of(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b''
        return payload.decode('utf-8', 'replace')


def parse_eml(raw):
    message = message_from_bytes(raw, policy=policy.default)
    headers = [(name, clean_space(value)) for name, value in message.raw_items()]
    html, text = None, None
    with_body = set()
    for preference in (('html',), ('plain',)):
        try:
            body = message.get_body(preferencelist=preference)
        except Exception:
            body = None
        if body is not None:
            with_body.add(id(body))
            if preference == ('html',):
                html = text_of(body)
            else:
                text = text_of(body)

    attachments, tree = [], []

    def walk(part, depth):
        if len(tree) >= MAX_PARTS:
            return
        content_type = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        node = {'depth': depth, 'content_type': content_type, 'filename': filename or '',
                'disposition': disposition or '', 'size': 0}
        tree.append(node)
        if content_type == 'message/rfc822':
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) and inner else inner
            data = inner.as_bytes(policy=policy.default) if hasattr(inner, 'as_bytes') else b''
            node['size'] = len(data)
            subject = clean_space(inner.get('Subject', '')) if hasattr(inner, 'get') else ''
            attachments.append({'filename': filename or (subject or 'attached message') + '.eml',
                                'content_type': content_type, 'data': data, 'content_id': '',
                                'inline': False, 'embedded_message': subject})
            return
        if part.is_multipart():
            for child in part.iter_parts():
                walk(child, depth + 1)
            return
        data = part.get_payload(decode=True) or b''
        node['size'] = len(data)
        if id(part) in with_body:
            return
        content_id = clean_space(part.get('Content-ID', '')).strip('<>')
        attachments.append({'filename': filename or '', 'content_type': content_type, 'data': data,
                            'content_id': content_id, 'inline': disposition == 'inline' or bool(content_id) and not filename,
                            'embedded_message': ''})

    walk(message, 0)

    def first(name):
        return clean_space(message.get(name, '') or '')

    return {
        'headers': headers,
        'get': lambda name: [clean_space(v) for v in (message.get_all(name) or [])],
        'subject': first('Subject'),
        'from': first('From'), 'sender': first('Sender'), 'reply_to': message.get_all('Reply-To') or [],
        'return_path': first('Return-Path'), 'to': message.get_all('To') or [], 'cc': message.get_all('Cc') or [],
        'bcc': message.get_all('Bcc') or [], 'date': first('Date'), 'message_id': first('Message-ID'),
        'html': html, 'text': text, 'attachments': attachments, 'tree': tree,
    }


def parse_msg(path):
    import extract_msg
    message = extract_msg.openMsg(path)
    try:
        transport = message.header
        headers = [(name, clean_space(value)) for name, value in transport.items()] if transport is not None else []

        def get(name):
            if transport is None:
                return []
            return [clean_space(v) for v in (transport.get_all(name) or [])]

        html = None
        try:
            body = message.htmlBody
            if body:
                html = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)
        except Exception:
            html = None
        try:
            text = message.body
        except Exception:
            text = None

        attachments, tree = [], [{'depth': 0, 'content_type': 'application/vnd.ms-outlook',
                                  'filename': '', 'disposition': '', 'size': 0}]
        for item in list(message.attachments)[:MAX_PARTS]:
            try:
                data = item.data
            except Exception:
                data = None
            filename = item.longFilename or item.shortFilename or item.displayName or ''
            content_type = (item.mimetype or 'application/octet-stream').lower()
            embedded = ''
            if data is not None and not isinstance(data, (bytes, bytearray)):
                # an attached Outlook item: keep its subject, export its bytes for hashing
                embedded = clean_space(getattr(data, 'subject', '') or 'attached message')
                filename = filename or embedded + '.msg'
                content_type = 'application/vnd.ms-outlook'
                try:
                    data = data.exportBytes()
                except Exception:
                    data = b''
            data = bytes(data or b'')
            content_id = clean_space(item.contentId or '').strip('<>')
            hidden = bool(getattr(item, 'hidden', False))
            attachments.append({'filename': filename, 'content_type': content_type, 'data': data,
                                'content_id': content_id, 'inline': hidden or (bool(content_id) and not embedded),
                                'embedded_message': embedded})
            tree.append({'depth': 1, 'content_type': content_type, 'filename': filename,
                         'disposition': 'inline' if hidden else 'attachment', 'size': len(data)})

        sender = message.sender or ''
        first_header = lambda name: (get(name) or [''])[0]
        return {
            'headers': headers, 'get': get, 'subject': clean_space(message.subject or ''),
            'from': first_header('From') or sender, 'sender': first_header('Sender'),
            'reply_to': get('Reply-To'), 'return_path': first_header('Return-Path'),
            'to': get('To') or ([message.to] if message.to else []),
            'cc': get('Cc') or ([message.cc] if message.cc else []),
            'bcc': [message.bcc] if message.bcc else [],
            'date': first_header('Date') or (str(message.date) if message.date else ''),
            'message_id': first_header('Message-ID') or clean_space(message.messageId or ''),
            'html': html, 'text': text, 'attachments': attachments, 'tree': tree,
        }
    finally:
        try:
            message.close()
        except Exception:
            pass


# ---------------------------------------------------------------- headers


def parse_received(values):
    hops = []
    for index, value in enumerate(reversed(values)):
        value = clean_space(value)
        section, _, date_text = value.rpartition(';')
        if not section:
            section, date_text = value, ''
        hop = {'index': index + 1, 'raw': value}
        for key, pattern in (('from', r'\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)'),
                             ('by', r'\bby\s+(\S+)'), ('with', r'\bwith\s+(\S+)'),
                             ('id', r'\bid\s+(\S+)'), ('for', r'\bfor\s+<?([^\s>;]+)')):
            found = re.search(pattern, section, re.IGNORECASE)
            hop[key] = found.group(1).strip() if found else ''
        ips = IPV4.findall(hop['from']) + IPV6_TAG.findall(hop['from'])
        hop['ips'] = list(dict.fromkeys(ip for ip in ips if _valid_ip(ip)))
        hop['public_ips'] = [ip for ip in hop['ips'] if public_ip(ip)]
        hop['date'] = clean_space(date_text)
        try:
            hop['timestamp'] = parsedate_to_datetime(hop['date']).timestamp() if hop['date'] else None
        except Exception:
            hop['timestamp'] = None
        hops.append(hop)
    previous = None
    for hop in hops:
        hop['delay_seconds'] = None
        if hop['timestamp'] is not None and previous is not None:
            hop['delay_seconds'] = int(hop['timestamp'] - previous)
        if hop['timestamp'] is not None:
            previous = hop['timestamp']
    return hops


def _valid_ip(value):
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


AUTH_METHODS = ('spf', 'dkim', 'dmarc', 'arc', 'compauth')


def parse_authentication(get):
    results = {}
    raw = get('Authentication-Results') + get('ARC-Authentication-Results')
    # the topmost Authentication-Results is the one added by the receiving server
    for value in get('Authentication-Results')[:1] or raw[:1]:
        for method in AUTH_METHODS:
            found = re.search(r'\b{}=(\w+)'.format(method), value, re.IGNORECASE)
            if found and method not in results:
                results[method] = found.group(1).lower()
    if 'spf' not in results:
        for value in get('Received-SPF')[:1]:
            results['spf'] = value.split()[0].lower() if value else ''
    return {'spf': results.get('spf', ''), 'dkim': results.get('dkim', ''), 'dmarc': results.get('dmarc', ''),
            'compauth': results.get('compauth', ''), 'raw': raw + get('Received-SPF'),
            'dkim_signatures': [_dkim_domain(v) for v in get('DKIM-Signature')]}


def _dkim_domain(value):
    found = re.search(r'\bd=([^;\s]+)', value)
    selector = re.search(r'\bs=([^;\s]+)', value)
    return {'domain': found.group(1).lower() if found else '', 'selector': selector.group(1) if selector else ''}


# ---------------------------------------------------------------- links


def unwrap_url(url):
    '''undo the rewriting mail gateways apply, so the real destination is analyzed'''
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = (parts.hostname or '').lower()
    query = parse_qs(parts.query)
    if host.endswith('safelinks.protection.outlook.com') and query.get('url'):
        return query['url'][0]
    if host == 'urldefense.proofpoint.com' and query.get('u'):
        return unquote(query['u'][0].replace('-', '%').replace('_', '/'))
    if host == 'urldefense.com' and parts.path.startswith('/v3/__'):
        return parts.path[len('/v3/__'):].split('__;', 1)[0] + (('?' + parts.query) if parts.query else '')
    if host in ('www.google.com', 'google.com') and parts.path == '/url' and (query.get('q') or query.get('url')):
        return (query.get('q') or query.get('url'))[0]
    return url


def url_flags(url, display=''):
    flags = []
    try:
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
    except ValueError:
        return ['malformed'], ''
    scheme = parts.scheme.lower()
    if scheme in ('javascript', 'vbscript', 'data'):
        flags.append('script_scheme')
    elif scheme == 'http':
        flags.append('not_https')
    elif scheme == 'file':
        flags.append('file_scheme')
    if host:
        if _valid_ip(host.strip('[]')):
            flags.append('ip_host')
        if 'xn--' in host:
            flags.append('punycode')
        if host in SHORTENERS or registered_domain(host) in SHORTENERS:
            flags.append('shortener')
        if '@' in (parts.netloc or ''):
            flags.append('credentials_in_url')
    if display:
        shown = display.strip().rstrip('.,;')
        if LOOKS_LIKE_URL.match(shown):
            shown_host = urlsplit(shown if '://' in shown else 'http://' + shown).hostname or ''
            if shown_host and host and registered_domain(shown_host) != registered_domain(host):
                flags.append('masked')
    return flags, host


class LinkTable:
    '''collects every link once, numbered so the rendered body can point back to it'''

    def __init__(self):
        self.items = []
        self.index = {}

    def add(self, url, display='', source='html'):
        url = (url or '').strip()
        if not url or url.startswith('#') or url.lower().startswith(('cid:', 'mailto:', 'tel:')):
            return None
        key = (url, display)
        if key in self.index:
            item = self.items[self.index[key]]
            if source not in item['sources']:
                item['sources'].append(source)
            return self.index[key]
        if len(self.items) >= MAX_LINKS:
            return None
        target = unwrap_url(url)
        flags, host = url_flags(target, display)
        if target != url:
            flags.append('wrapped')
        self.items.append({'id': len(self.items), 'url': url, 'target': target, 'display': display[:300],
                           'host': host, 'domain': registered_domain(host), 'flags': flags, 'sources': [source]})
        self.index[key] = len(self.items) - 1
        return self.index[key]


# ---------------------------------------------------------------- rendering


def _css_scrub(css, counter):
    counter.extend(CSS_IMPORT.findall(css))
    css = CSS_IMPORT.sub('', css)
    css = CSS_DANGEROUS.sub('', css)

    def replace(match):
        target = match.group(2).strip()
        if target.lower().startswith('data:image/'):
            return match.group(0)
        counter.append(target)
        return 'none'
    return CSS_URL.sub(replace, css)


def _remote_host(value):
    try:
        return urlsplit(value.strip()).hostname or ''
    except ValueError:
        return ''


def render_html(html, links, cid_map):
    '''inert copy of the HTML body: same markup and CSS, nothing that runs or fetches'''
    soup = BeautifulSoup(html, 'html.parser')
    remote = []
    forms = 0
    for node in soup.find_all(string=lambda text: isinstance(text, Comment)):
        node.extract()
    for tag in soup.find_all(DROP_TAGS):
        tag.decompose()
    for tag in soup.find_all('noscript'):
        tag.unwrap()
    for tag in soup.find_all('style'):
        tag.string = _css_scrub(tag.get_text(), remote)
    for tag in soup.find_all(True):
        name = tag.name.lower()
        if name == 'form':
            forms += 1
        for attribute in list(tag.attrs):
            lower = attribute.lower()
            value = tag.attrs[attribute]
            value = ' '.join(value) if isinstance(value, list) else str(value)
            if lower.startswith('on') or lower in ('formaction', 'action', 'ping', 'target', 'srcdoc'):
                del tag.attrs[attribute]
            elif lower == 'style':
                tag.attrs[attribute] = _css_scrub(value, remote)
            elif lower in ('href', 'xlink:href') and name in ('a', 'area'):
                del tag.attrs[attribute]
                link_id = links.add(value, clean_space(tag.get_text()), 'html')
                tag.attrs['href'] = '#'
                if link_id is not None:
                    tag.attrs['data-up-link'] = str(link_id)
            elif lower in ('href', 'xlink:href'):
                # <use>, <image> in SVG and the like: never fetch
                if not value.strip().startswith('#'):
                    remote.append(value)
                    del tag.attrs[attribute]
            elif lower == 'src' and name == 'img':
                source = value.strip()
                if source.lower().startswith('cid:'):
                    tag.attrs['src'] = cid_map.get(unquote(source[4:]).strip('<>'), BLANK_IMAGE)
                elif source.lower().startswith('data:image/') and not source.lower().startswith('data:image/svg'):
                    pass
                else:
                    remote.append(source)
                    tag.attrs['src'] = BLANK_IMAGE
                    tag.attrs['data-up-blocked'] = _remote_host(source)[:200]
            elif lower in URL_ATTRS:
                if not value.strip().lower().startswith('data:image/'):
                    if value.strip():
                        remote.append(value)
                    del tag.attrs[attribute]
    body = soup.find('body')
    if body is not None:
        # <style> blocks in <head> carry the layout; those inside <body> travel with it
        styles = ''.join(str(tag) for tag in soup.find_all('style') if tag.find_parent('body') is None)
        attributes = ''.join(' {}="{}"'.format(escape(k), escape(' '.join(v) if isinstance(v, list) else str(v)))
                             for k, v in body.attrs.items())
        markup = '<body{}>{}</body>'.format(attributes, body.decode_contents())
    else:
        for tag in soup.find_all('title'):
            tag.decompose()
        for tag in soup.find_all(['html', 'head']):
            tag.unwrap()
        styles, markup = '', '<body>{}</body>'.format(str(soup))
    hosts = sorted({_remote_host(item) for item in remote if _remote_host(item)})
    return document(styles, markup), {'count': len(remote), 'hosts': hosts[:100]}, forms


def render_text(text, links):
    parts, last = [], 0
    for match in URL_IN_TEXT.finditer(text):
        url = match.group(1).rstrip('.,;:)!?]\'"')
        start, end = match.start(1), match.start(1) + len(url)
        parts.append(escape(text[last:start]))
        link_id = links.add(url if '://' in url else 'http://' + url, url, 'text')
        anchor = '<a href="#"{}>{}</a>'.format(
            ' data-up-link="{}"'.format(link_id) if link_id is not None else '', escape(url))
        parts.append(anchor)
        last = end
    parts.append(escape(text[last:]))
    body = ('<body><pre style="white-space: pre-wrap; word-wrap: break-word; font: 14px/1.5 '
            '-apple-system, Segoe UI, Arial, sans-serif; margin: 0">{}</pre></body>').format(''.join(parts))
    return document('', body)


def document(styles, body):
    return ('<!DOCTYPE html><html><head><meta charset="utf-8">'
            '<style>html{{background:#fff;color:#111}}body{{margin:16px;font-family:-apple-system,Segoe UI,'
            'Arial,sans-serif}}a[data-up-link]{{cursor:pointer}}img[data-up-blocked]{{outline:1px dashed #c9ccd3;'
            'background:#f3f4f6}}</style>{}</head>{}</html>').format(styles, body)


# ---------------------------------------------------------------- attachments


def detect_type(data):
    head = data[:2048]
    if head.startswith(b'MZ'):
        return 'pe', 'Windows executable (PE)'
    if head.startswith(b'PK\x03\x04'):
        try:
            names = ZipFile(BytesIO(data)).namelist()
        except (BadZipFile, Exception):
            return 'zip', 'ZIP archive'
        if '[Content_Types].xml' in names:
            return 'ooxml', 'Office Open XML document'
        return 'zip', 'ZIP archive'
    if head.startswith(OLE_MAGIC):
        return 'ole', 'OLE compound file (legacy Office / MSG)'
    if head.startswith(b'%PDF'):
        return 'pdf', 'PDF document'
    if head.startswith(b'{\\rt'):
        return 'rtf', 'RTF document'
    if head.startswith(b'Rar!'):
        return 'rar', 'RAR archive'
    if head.startswith(b'7z\xbc\xaf\x27\x1c'):
        return '7z', '7-Zip archive'
    if head.startswith(b'\x1f\x8b'):
        return 'gzip', 'GZIP archive'
    if head.startswith(b'MSCF'):
        return 'cab', 'CAB archive'
    if head.startswith(b'L\x00\x00\x00\x01\x14\x02\x00'):
        return 'lnk', 'Windows shortcut (LNK)'
    if head.startswith(b'\x89PNG'):
        return 'png', 'PNG image'
    if head.startswith(b'\xff\xd8\xff'):
        return 'jpeg', 'JPEG image'
    if head.startswith((b'GIF87a', b'GIF89a')):
        return 'gif', 'GIF image'
    if head.startswith((b'II*\x00', b'MM\x00*')):
        return 'tiff', 'TIFF image'
    if len(data) > 0x8006 and data[0x8001:0x8006] == b'CD001':
        return 'iso', 'ISO disk image'
    lowered = head.lstrip(b'\xef\xbb\xbf \t\r\n').lower()
    if lowered.startswith((b'<!doctype html', b'<html', b'<head', b'<body', b'<script')) or b'<html' in lowered[:512]:
        return 'html', 'HTML document'
    if lowered.startswith(b'<svg') or (lowered.startswith(b'<?xml') and b'<svg' in lowered):
        return 'svg', 'SVG image'
    return 'data', 'Unknown / data'


def extension(filename):
    name = (filename or '').lower().rstrip(' .')
    return name.rsplit('.', 1)[1] if '.' in name else ''


def attachment_flags(filename, data, family):
    flags = []
    ext = extension(filename)
    if '\u202e' in (filename or ''):
        flags.append('rtlo_filename')
    stem_ext = extension((filename or '').lower().rstrip(' .').rsplit('.', 1)[0]) if ext else ''
    risky = EXECUTABLE_EXT | DISK_IMAGE_EXT | MACRO_EXT | HTML_EXT | ONENOTE_EXT
    if ext in risky and stem_ext and stem_ext != ext and len(stem_ext) <= 4 and stem_ext.isalnum():
        flags.append('double_extension')
    if ext in EXECUTABLE_EXT or family in ('pe', 'lnk'):
        flags.append('executable')
    if ext in DISK_IMAGE_EXT or family == 'iso':
        flags.append('disk_image')
    if ext in MACRO_EXT:
        flags.append('macro_enabled')
    if family == 'ooxml':
        try:
            if any(name.lower().endswith('vbaproject.bin') for name in ZipFile(BytesIO(data)).namelist()):
                flags.append('contains_macros')
        except Exception:
            pass
    if ext in LEGACY_OFFICE_EXT or (family == 'ole' and ext not in ('msg',)):
        flags.append('legacy_office')
    if ext in HTML_EXT or family in ('html', 'svg'):
        flags.append('html')
    if ext in ONENOTE_EXT:
        flags.append('onenote')
    if ext in ARCHIVE_EXT or family in ('zip', 'rar', '7z', 'gzip', 'cab'):
        flags.append('archive')
        if family == 'zip':
            try:
                if any(info.flag_bits & 0x1 for info in ZipFile(BytesIO(data)).infolist()):
                    flags.append('encrypted_archive')
            except Exception:
                pass
    expected = EXPECTED_FAMILY.get(ext)
    if expected and family != 'data' and expected != family and not (expected == 'html' and family == 'svg'):
        flags.append('type_mismatch')
    return flags


# ---------------------------------------------------------------- indicators

INDICATORS = {
    'spf_fail': ('high', 'SPF failed', 'The sending server is not authorized by the sender domain.'),
    'spf_softfail': ('medium', 'SPF soft fail', 'The sending server is probably not authorized by the sender domain.'),
    'dkim_fail': ('high', 'DKIM failed', 'The DKIM signature did not verify.'),
    'dmarc_fail': ('high', 'DMARC failed', 'The From domain did not pass DMARC alignment.'),
    'no_auth_results': ('info', 'No authentication results', 'The message carries no Authentication-Results header to check.'),
    'reply_to_mismatch': ('medium', 'Reply-To differs from From', 'Replies go to a different domain than the sender.'),
    'return_path_mismatch': ('low', 'Return-Path differs from From', 'Bounces go to a different domain than the sender.'),
    'display_name_spoof': ('high', 'Display name holds another address', 'The display name shows an address that is not the real sender.'),
    'message_id_mismatch': ('low', 'Message-ID domain differs', 'The Message-ID was generated by a different domain than the sender.'),
    'masked_links': ('high', 'Masked links', 'Link text shows one domain but the link leads to another.'),
    'script_links': ('high', 'Script links', 'Links use javascript:, vbscript: or data: URLs.'),
    'ip_links': ('medium', 'Links to IP addresses', 'Links point to a bare IP address instead of a domain.'),
    'punycode_links': ('medium', 'Punycode domains', 'Links use internationalized (xn--) domains that can imitate others.'),
    'shortener_links': ('low', 'URL shorteners', 'Links hide their destination behind a shortener.'),
    'html_form': ('high', 'Form inside the message', 'The body contains a form, typical of credential harvesting.'),
    'remote_content': ('info', 'Remote content', 'The body loads images or styles from the internet (tracking pixels).'),
    'executable_attachment': ('high', 'Executable attachment', 'An attachment can run code when opened.'),
    'macro_attachment': ('high', 'Macro-capable attachment', 'An Office attachment contains or allows macros.'),
    'html_attachment': ('medium', 'HTML attachment', 'HTML attachments are used for smuggling and local fake logins.'),
    'disk_image_attachment': ('high', 'Disk image attachment', 'ISO/IMG/VHD files bypass Mark-of-the-Web protections.'),
    'onenote_attachment': ('high', 'OneNote attachment', 'OneNote files are used to deliver embedded scripts.'),
    'archive_attachment': ('low', 'Archive attachment', 'An archive may hide its contents from mail scanning.'),
    'encrypted_archive': ('high', 'Password-protected archive', 'An encrypted archive hides its contents from scanners.'),
    'double_extension': ('high', 'Double extension', 'An attachment name hides its real type behind a second extension.'),
    'rtlo_filename': ('high', 'Right-to-left override in filename', 'The attachment name uses U+202E to disguise its extension.'),
    'type_mismatch': ('medium', 'Attachment type mismatch', 'An attachment content does not match its extension.'),
}
SEVERITY_ORDER = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def indicators(result, auth, links, attachments, remote, forms):
    found = []

    def add(key, detail=''):
        severity, title, description = INDICATORS[key]
        found.append({'id': key, 'severity': severity, 'title': title, 'description': description,
                      'detail': detail})

    if auth['spf'] in ('fail', 'hardfail'):
        add('spf_fail', auth['spf'])
    elif auth['spf'] == 'softfail':
        add('spf_softfail')
    if auth['dkim'] in ('fail', 'permerror'):
        add('dkim_fail', auth['dkim'])
    if auth['dmarc'] in ('fail', 'permerror'):
        add('dmarc_fail', auth['dmarc'])
    if not (auth['spf'] or auth['dkim'] or auth['dmarc']):
        add('no_auth_results')

    sender = result['from']
    sender_domain = registered_domain(address_domain(sender['address']))
    for reply in result['reply_to']:
        reply_domain = registered_domain(address_domain(reply['address']))
        if sender_domain and reply_domain and reply_domain != sender_domain:
            add('reply_to_mismatch', reply['address'])
            break
    return_domain = registered_domain(address_domain(result['return_path']['address']))
    if sender_domain and return_domain and return_domain != sender_domain:
        add('return_path_mismatch', result['return_path']['address'])
    for shown in EMAIL_IN_TEXT.findall(sender['name'] or ''):
        if shown.lower() != sender['address']:
            add('display_name_spoof', shown)
            break
    message_id_domain = registered_domain(result['message_id'].strip('<>').rpartition('@')[2]) if '@' in result['message_id'] else ''
    if sender_domain and message_id_domain and message_id_domain != sender_domain:
        add('message_id_mismatch', message_id_domain)

    for key, flag in (('masked_links', 'masked'), ('script_links', 'script_scheme'), ('ip_links', 'ip_host'),
                      ('punycode_links', 'punycode'), ('shortener_links', 'shortener')):
        hits = [link for link in links if flag in link['flags']]
        if hits:
            add(key, '{} link{}'.format(len(hits), '' if len(hits) == 1 else 's'))
    if forms:
        add('html_form', '{} form{}'.format(forms, '' if forms == 1 else 's'))
    if remote['count']:
        add('remote_content', ', '.join(remote['hosts'][:5]))

    for key, flag in (('executable_attachment', 'executable'), ('disk_image_attachment', 'disk_image'),
                      ('onenote_attachment', 'onenote'), ('html_attachment', 'html'),
                      ('encrypted_archive', 'encrypted_archive'), ('archive_attachment', 'archive'),
                      ('double_extension', 'double_extension'), ('rtlo_filename', 'rtlo_filename'),
                      ('type_mismatch', 'type_mismatch')):
        hits = [item['filename'] or item['sha256'][:12] for item in attachments if flag in item['flags']]
        if hits:
            add(key, ', '.join(hits[:5]))
    macro = [item['filename'] for item in attachments
             if {'macro_enabled', 'contains_macros', 'legacy_office'} & set(item['flags'])]
    if macro:
        add('macro_attachment', ', '.join(macro[:5]))
    found.sort(key=lambda item: -SEVERITY_ORDER[item['severity']])
    return found


def verdict(found):
    top = max((SEVERITY_ORDER[item['severity']] for item in found), default=0)
    return {3: 'suspicious', 2: 'review', 1: 'low', 0: 'clean'}[top]


# ---------------------------------------------------------------- entry point


def analyze(raw, filename, path=None):
    '''raw bytes of the uploaded file -> (analysis dict, rendered message HTML)'''
    kind = 'msg' if raw.startswith(OLE_MAGIC) else 'eml'
    parsed = parse_msg(path) if kind == 'msg' else parse_eml(raw)
    get = parsed['get']

    attachments, cid_map = [], {}
    for item in parsed['attachments']:
        data = item['data']
        family, description = detect_type(data)
        record = {'filename': item['filename'], 'content_type': item['content_type'], 'size': len(data),
                  'detected': family, 'detected_label': description, 'content_id': item['content_id'],
                  'inline': item['inline'], 'embedded_message': item['embedded_message'], **hashes(data)}
        record['flags'] = attachment_flags(item['filename'], data, family)
        attachments.append(record)
        if item['content_id'] and family in ('png', 'jpeg', 'gif') and len(data) <= 5 * 1024 * 1024:
            mime = {'png': 'image/png', 'jpeg': 'image/jpeg', 'gif': 'image/gif'}[family]
            cid_map[item['content_id']] = 'data:{};base64,{}'.format(mime, b64encode(data).decode())

    links = LinkTable()
    html, text = parsed['html'], parsed['text']
    remote, forms = {'count': 0, 'hosts': []}, 0
    if html:
        rendered, remote, forms = render_html(html, links, cid_map)
        if text:
            for match in URL_IN_TEXT.finditer(text):
                url = match.group(1).rstrip('.,;:)!?]\'"')
                links.add(url if '://' in url else 'http://' + url, url, 'text')
    elif text:
        rendered = render_text(text, links)
    else:
        rendered = document('', '<body><p style="color:#6b7280">This message has no text or HTML body.</p></body>')

    result = {
        'subject': parsed['subject'],
        'from': mailbox(parsed['from']),
        'sender': mailbox(parsed['sender']) if parsed['sender'] else None,
        'reply_to': mailbox_list(parsed['reply_to']),
        'return_path': mailbox(parsed['return_path']),
        'to': mailbox_list(parsed['to']), 'cc': mailbox_list(parsed['cc']), 'bcc': mailbox_list(parsed['bcc']),
        'date': parsed['date'], 'message_id': parsed['message_id'],
    }
    auth = parse_authentication(get)
    hops = parse_received(get('Received'))
    found = indicators(result, auth, links.items, attachments, remote, forms)

    emails = [result['from']['address'], result['return_path']['address']] + \
        [item['address'] for item in result['reply_to']] + ([result['sender']['address']] if result['sender'] else [])
    ips = [ip for hop in hops for ip in hop['public_ips']] + \
        [link['host'].strip('[]') for link in links.items
         if 'ip_host' in link['flags'] and public_ip(link['host'].strip('[]'))]
    for name in ('X-Originating-IP', 'X-Sender-IP'):
        for value in get(name):
            ips += [ip for ip in IPV4.findall(value) if public_ip(ip)]
    analysis = {
        'format': kind,
        'filename': filename,
        'size': len(raw),
        'hashes': hashes(raw),
        'message': result,
        'mailer': (get('X-Mailer') or get('User-Agent') or [''])[0],
        'originating_ip': (get('X-Originating-IP') or get('X-Sender-IP') or [''])[0],
        'headers': [[name, value] for name, value in parsed['headers']],
        'received': [{key: value for key, value in hop.items() if key != 'timestamp'} for hop in hops],
        'authentication': auth,
        'body': {'has_html': bool(html), 'has_text': bool(text),
                 'text': (text or '')[:MAX_TEXT], 'text_truncated': len(text or '') > MAX_TEXT,
                 'html_source': (html or '')[:MAX_HTML_SOURCE], 'html_truncated': len(html or '') > MAX_HTML_SOURCE},
        'links': links.items,
        'attachments': attachments,
        'mime_tree': parsed['tree'],
        'remote_content': remote,
        'forms': forms,
        'indicators': found,
        'verdict': verdict(found),
        'iocs': {
            'urls': list(dict.fromkeys(link['target'] for link in links.items
                                       if link['target'].lower().startswith(('http://', 'https://', 'ftp://')))),
            'domains': list(dict.fromkeys(link['domain'] for link in links.items
                                          if link['domain'] and 'ip_host' not in link['flags'])),
            'ips': list(dict.fromkeys(ips)),
            'emails': list(dict.fromkeys(e for e in emails if e)),
            'sha256': list(dict.fromkeys(item['sha256'] for item in attachments if item['size'])),
        },
    }
    return analysis, rendered
