'''
    mailbox -> entry point
    Reads the uploaded message from /in (read-only) and writes email.json and message.html
    to /out. The container has no network, so nothing in the message can reach out.
'''

import sys
from json import dump
from os import path
from qbmail import analyze

INPUT_DIR = '/in'
OUTPUT_DIR = '/out'


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
    analysis, rendered = analyze(raw, args[1] if len(args) > 1 else name, source)
    with open(path.join(OUTPUT_DIR, 'message.html'), 'w', encoding='utf-8') as handle:
        handle.write(rendered)
    with open(path.join(OUTPUT_DIR, 'email.json'), 'w', encoding='utf-8') as handle:
        dump(analysis, handle, ensure_ascii=False)
    print('Parsed {} message: {} links, {} attachments, {} indicators'.format(
        analysis['format'], len(analysis['links']), len(analysis['attachments']), len(analysis['indicators'])))
    print('Done!!')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
