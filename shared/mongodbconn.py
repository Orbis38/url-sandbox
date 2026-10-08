'''
    __G__ = "(G)bd249ce4"
    shared -> monogo client
'''

from os import environ
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
from datetime import datetime
from hashlib import sha256
from shared.settings import json_settings, defaultdb

CLIENT = MongoClient(json_settings[environ["project_env"]]["mongo_settings"])


def ensure_indexes():
    db = CLIENT[defaultdb['dbname']]
    tasks = db[defaultdb['taskdblogscoll']]
    # Existing installations may contain duplicate task records; do not break startup.
    tasks.create_index('task')
    tasks.create_index([('owner_id', 1), ('start', -1)])
    tasks.create_index('start')
    db[defaultdb['reportscoll']].create_index([('task', 1), ('type', 1)])
    db[defaultdb['taskfileslogscoll']].create_index('task')
    db['fs.files'].create_index([('task', 1), ('contentType', 1)])
    db[defaultdb['artifactscoll']].create_index([('task', 1), ('kind', 1)], unique=True)
    db[defaultdb['loglinescoll']].create_index([('owner_id', 1), ('_id', 1)])
    db[defaultdb['loglinescoll']].create_index([('task', 1), ('owner_id', 1), ('_id', 1)])
    db['login_attempts'].create_index('expires_at', expireAfterSeconds=0)


def update_task(database_name, collection_name, task, log):
    '''
    simple item update
    '''
    db = CLIENT[database_name]
    owner = db[collection_name].find_one_and_update(
        {'task': task}, {'$set': {'has_logs': True}},
        projection={'owner_id': 1}, upsert=True)
    if owner and owner.get('owner_id'):
        db[defaultdb['loglinescoll']].insert_one({
            'task': task, 'owner_id': owner['owner_id'],
            'message': log, 'time': datetime.utcnow(),
        })


def update_task_by_uuid(database_name, collection_name, task, _set):
    '''
    simple item update
    '''
    CLIENT[database_name][collection_name].update_one({'task': task}, {'$set': _set})


def add_item(database_name, collection_name, _set):
    '''
    add an item and return it otherwise False
    '''
    item = CLIENT[database_name][collection_name].insert_one(_set)
    if item is not None:
        return item
    return False


def find_item(database_name, collection_name, _set):
    '''
    find an item and return it otherwise return empty string
    '''
    item = CLIENT[database_name][collection_name].find_one(_set, {'_id': False})
    if item is not None:
        return item
    return ""


def add_item_fs(database_name, collection_name, file_buffer, name, _set, task, _type, time):
    '''
    find an item to FS
    '''
    item = GridFS(CLIENT[database_name]).put(file_buffer, filename=name, task=task, content_type=_type, encoding='utf-8')
    if item is not None:
        metadata = {"task": task, "type": _type, "file": ObjectId(item), "time": time}
        if isinstance(_set, dict):
            metadata.update(_set)
        item = CLIENT[database_name][collection_name].insert_one(metadata)
        if item is not None:
            return item
    return False


def get_it_fs(database_name, _set):
    '''
    get an item from  FS
    '''
    item = GridFS(CLIENT[database_name]).find_one(_set)
    if item is not None:
        return item.read()
    return False


def put_artifact(database_name, task, kind, payload, mime):
    db = CLIENT[database_name]
    collection = db[defaultdb['artifactscoll']]
    digest = sha256(payload).hexdigest()
    previous = collection.find_one({'task': task, 'kind': kind})
    if previous and previous.get('sha256') == digest:
        return previous['file']
    fs = GridFS(db)
    file_id = fs.put(payload, task=task, artifact_kind=kind, content_type=mime)
    collection.update_one({'task': task, 'kind': kind}, {'$set': {
        'file': file_id, 'content_type': mime, 'sha256': digest,
        'updated_at': datetime.utcnow(),
    }}, upsert=True)
    if previous:
        fs.delete(previous['file'])
    return file_id


def open_artifact(database_name, task, kind):
    db = CLIENT[database_name]
    metadata = db[defaultdb['artifactscoll']].find_one({'task': task, 'kind': kind})
    if not metadata:
        return None
    return GridFS(db).get(metadata['file']), metadata


def get_artifact(database_name, task, kind):
    artifact = open_artifact(database_name, task, kind)
    if not artifact:
        return None
    file, metadata = artifact
    return file.read(), metadata['content_type']


def get_task_logs(database_name, task, owner_id, legacy=()):
    records = CLIENT[database_name][defaultdb['loglinescoll']].find(
        {'task': task, 'owner_id': owner_id}, {'message': 1}).sort('_id', 1)
    return list(legacy) + [record['message'] for record in records]
