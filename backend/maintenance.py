"""Periodic housekeeping. Never retries jobs or stops running sandbox containers."""
import json
import re
from datetime import datetime, timedelta, timezone
from os import environ, path
from time import sleep, monotonic
from docker import from_env
from shared.mongodbconn import CLIENT
from shared.settings import defaultdb, json_settings
from shared.retention import cleanup_expired_analyses

BOX_NAME = re.compile(r'^url-sandbox_box_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$')


def cleanup_finished_containers(client, output_folder, now=None):
    now = datetime.now(timezone.utc) if now is None else now
    removed = 0
    for container in client.containers.list(all=True, filters={'status': 'exited', 'name': 'url-sandbox_box_'}):
        match = BOX_NAME.fullmatch(container.name)
        config = container.attrs.get('Config', {})
        if not match or config.get('Image') != 'url-sandbox-box':
            continue
        finished = container.attrs.get('State', {}).get('FinishedAt')
        if not finished:
            continue
        ended = datetime.fromisoformat(finished.replace('Z', '+00:00'))
        if (now - ended).total_seconds() < 30:
            continue
        container.remove()  # Never force-remove a live container.
        removed += 1
        task_dir = path.join(output_folder, match.group(1))
        meta_file = path.join(task_dir, 'vnc_session.json')
        if path.isfile(meta_file) and not path.islink(meta_file):
            with open(meta_file) as source:
                metadata = json.load(source)
            metadata['status'] = 'ended'
            metadata.pop('vnc_token', None)
            with open(meta_file, 'w') as output:
                json.dump(metadata, output)
    return removed


def mark_interrupted_tasks(now=None):
    now = datetime.utcnow() if now is None else now
    settings = json_settings[environ.get('project_env', 'docker')]
    cutoff = now - timedelta(seconds=settings['worker']['task_time_limit'] + 60)
    collection = CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']]
    result = collection.update_many({'end': None, '$or': [
        {'status': 'running', 'started_at': {'$lt': cutoff}},
        {'status': {'$exists': False}, 'has_logs': True, 'start': {'$lt': cutoff}},
    ]}, {'$set': {'status': 'interrupted', 'end': now,
                  'error': 'Worker execution ended without completion; no automatic retry'}})
    return result.modified_count


def main():
    settings = json_settings[environ['project_env']]
    client = from_env()
    next_retention = 0
    while True:
        try:
            removed = cleanup_finished_containers(client, settings['output_folder'])
            interrupted = mark_interrupted_tasks()
            if monotonic() >= next_retention:
                cleanup_expired_analyses(settings.get('retention_days', 60))
                next_retention = monotonic() + 3600
            if removed or interrupted:
                print(f'Housekeeping: removed {removed} stopped boxes; marked {interrupted} interrupted tasks', flush=True)
        except Exception as error:
            print(f'Housekeeping error: {error}', flush=True)
        sleep(60)


if __name__ == '__main__':
    main()
