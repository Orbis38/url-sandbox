'''
    backend -> email report
    Stores what the mailbox container produced: the analysis JSON (the report), the inert
    message rendering (an artifact served to the report's iframe) and a few queue fields.
'''

from datetime import datetime
from json import loads, dumps
from os import path
from shared.settings import defaultdb
from shared.mongodbconn import add_item_fs, put_artifact, update_task_by_uuid

MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def read_output(folder, name):
    filename = path.join(folder, name)
    if path.islink(filename) or not path.isfile(filename):
        raise ValueError('Missing {}'.format(name))
    if path.getsize(filename) > MAX_OUTPUT_BYTES:
        raise ValueError('{} is too large'.format(name))
    with open(filename, 'rb') as handle:
        return handle.read()


def make_email_report(parsed, folder):
    '''returns the analysis dict that was stored'''
    analysis = loads(read_output(folder, 'email.json').decode('utf-8'))
    rendered = read_output(folder, 'message.html')
    add_item_fs(defaultdb['dbname'], defaultdb['reportscoll'],
                dumps(analysis, ensure_ascii=False).encode('utf-8'), 'email.json', {},
                parsed['task'], 'application/json', datetime.utcnow())
    put_artifact(defaultdb['dbname'], parsed['task'], 'email_message', rendered, 'text/html')
    message = analysis.get('message') or {}
    update_task_by_uuid(defaultdb['dbname'], defaultdb['taskdblogscoll'], parsed['task'], {
        'subject': (message.get('subject') or '')[:300],
        'email_from': ((message.get('from') or {}).get('address') or '')[:300],
        'verdict': analysis.get('verdict') or '',
    })
    return analysis
