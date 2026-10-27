'''
    mailbox -> entry point
    Reads the uploaded message from /in (read-only) and writes to /out: email.json, message.html,
    rendered/<sha256>.html (inert HTML attachments) and samples/<sha256>.zip (every attachment and
    extracted file, AES-encrypted with the password "infected"). The container has no network,
    so nothing in the message can reach out.
'''

import sys
from json import dump
from os import path, makedirs
from qbmail import analyze
from attachments import load_rules

INPUT_DIR = '/in'
OUTPUT_DIR = '/out'
RULES_DIRS = ['/rules']
SAMPLE_PASSWORD = b'infected'
MAX_SAMPLES_BYTES = 200 * 1024 * 1024


def safe_name(name):
    name = path.basename(str(name or '').replace('\\', '/')).strip() or 'attachment'
    return ''.join(ch if ch.isprintable() and ch not in '/\\:*?"<>|' else '_' for ch in name)[:150]


def write_samples(samples, folder):
    '''one encrypted zip per file, plus all.zip with everything (the analyst's usual "infected" zip)'''
    import pyzipper
    makedirs(folder, exist_ok=True)
    total = 0
    index = {}
    with pyzipper.AESZipFile(path.join(folder, 'all.zip'), 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as bundle:
        bundle.setpassword(SAMPLE_PASSWORD)
        for digest, (name, data) in samples.items():
            total += len(data)
            if total > MAX_SAMPLES_BYTES:
                break
            member = '{}_{}'.format(digest[:8], safe_name(name))
            with pyzipper.AESZipFile(path.join(folder, digest + '.zip'), 'w', compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as single:
                single.setpassword(SAMPLE_PASSWORD)
                single.writestr(safe_name(name), data)
            bundle.writestr(member, data)
            index[digest] = safe_name(name)
    return index


def main(args):
    '''args: the input file name inside /in, then optionally the analyst's original file name'''
    if not args:
        print('usage: run.py <input file name> [original file name]')
        return 0
    name = path.basename(args[0])
    source = path.join(INPUT_DIR, name)
    if name != args[0] or not path.isfile(source) or path.islink(source):
        print('Input file not found')
        return 1
    with open(source, 'rb') as handle:
        raw = handle.read()
    extras = {}
    rules = load_rules(RULES_DIRS)
    analysis, rendered = analyze(raw, args[1] if len(args) > 1 else name, source, extras, rules)
    analysis['yara_rules'] = len(rules or {})
    with open(path.join(OUTPUT_DIR, 'message.html'), 'w', encoding='utf-8') as handle:
        handle.write(rendered)
    if extras.get('rendered'):
        makedirs(path.join(OUTPUT_DIR, 'rendered'), exist_ok=True)
        for digest, html in extras['rendered'].items():
            with open(path.join(OUTPUT_DIR, 'rendered', digest + '.html'), 'w', encoding='utf-8') as handle:
                handle.write(html)
    if extras.get('samples'):
        analysis['samples'] = sorted(write_samples(extras['samples'], path.join(OUTPUT_DIR, 'samples')))
    with open(path.join(OUTPUT_DIR, 'email.json'), 'w', encoding='utf-8') as handle:
        dump(analysis, handle, ensure_ascii=False)
    print('Parsed {} message: {} links, {} attachments, {} indicators'.format(
        analysis['format'], len(analysis['links']), len(analysis['attachments']), len(analysis['indicators'])))
    print('Done!!')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
