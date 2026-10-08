'''
    __G__ = "(G)bd249ce4"
    shared -> logger
'''

from sys import stdout
from datetime import datetime
from contextlib import contextmanager
from shared.settings import defaultdb
from shared.mongodbconn import CLIENT, add_item, update_task, update_task_by_uuid
from pymongo import ReturnDocument
from uuid import uuid4


@contextmanager
def ignore_exception(*exceptions):
    '''
    catch exception
    '''
    try:
        yield
    except exceptions as error:
        pass


def setup_task_logger(parsed):
    '''
    setup the dynamic logger for the task
    '''
    log_string("Setup task {} logger".format(parsed['task']), "Yellow")
    collection = CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']]
    claimed = collection.find_one_and_update(
        {'task': parsed['task'], 'owner_id': parsed.get('owner_id'), 'end': None,
         '$or': [{'status': 'queued'}, {'status': {'$exists': False}, 'has_logs': {'$ne': True}, 'logs': []}]},
        {'$set': {'status': 'running', 'started_at': datetime.utcnow(), 'execution_id': str(uuid4())}},
        return_document=ReturnDocument.AFTER)
    return claimed is not None


def cancel_task_logger(task, status='completed', error=None):
    '''
    setup the dynamic logger for the task
    '''
    log_string("Closing task {} logger".format(task), "Yellow")
    CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']].update_one(
        {'task': task, 'status': 'running'},
        {'$set': {'end': datetime.utcnow(), 'status': status, 'error': error}})


def log_string(_str, color=None, task=None):
    '''
    output str with color and symbol (they are all as info)
    '''
    ctime = datetime.utcnow()
    if _str.isspace() or len(_str) == 0:
        _str = "None"
    if task is None:
        add_item(defaultdb["dbname"], defaultdb["alllogscoll"], {'time': ctime, 'message': _str})
    else:
        update_task(defaultdb["dbname"], defaultdb["taskdblogscoll"], task, "{} > {}".format(ctime, _str))
    print("{} {}".format(_str, task))
    stdout.flush()
