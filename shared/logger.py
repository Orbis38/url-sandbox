'''
    __G__ = "(G)bd249ce4"
    shared -> logger
'''

from sys import stdout
from datetime import datetime
from contextlib import contextmanager
from shared.settings import defaultdb
from shared.mongodbconn import CLIENT, add_item, update_task, update_task_by_uuid


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
    temp_dict = parsed.copy()
    temp_dict.update({"start": datetime.utcnow(), "end": None, "logs": []})
    CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']].update_one(
        {'task': parsed['task']}, {'$setOnInsert': temp_dict}, upsert=True)


def cancel_task_logger(task):
    '''
    setup the dynamic logger for the task
    '''
    log_string("Closing task {} logger".format(task), "Yellow")
    update_task_by_uuid(defaultdb["dbname"], defaultdb["taskdblogscoll"], task, {"end": datetime.utcnow()})


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
