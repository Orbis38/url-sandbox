'''
    shared -> retention policy
    User accounts are kept indefinitely.
    Analyses, reports, logs, and sandbox output are kept for 60 days.
'''

from os import path, environ
import shutil
from datetime import datetime, timedelta
from gridfs import GridFS
from shared.settings import defaultdb, json_settings
from shared.mongodbconn import CLIENT
from uuid import UUID


def cleanup_expired_analyses(days=60, project_env=None):
    '''
    Clean up analysis tasks and associated artifacts older than specified days.
    User accounts ('users') are explicitly preserved indefinitely.
    '''
    if project_env is None:
        project_env = environ.get("project_env", "docker")

    try:
        db_name = defaultdb["dbname"]
        cutoff = datetime.utcnow() - timedelta(days=days)

        taskdb_coll = CLIENT[db_name][defaultdb["taskdblogscoll"]]
        # Find tasks where start is older than cutoff date
        expired_docs = taskdb_coll.find({"start": {"$lt": cutoff}}, {'task': 1})

        gfs = GridFS(CLIENT[db_name])
        output_folder = json_settings[project_env]["output_folder"]
        cleaned_count = 0

        for task_doc in expired_docs:
            task_id = task_doc.get("task")
            if not task_id:
                continue

            # 1. Clean up GridFS files associated with this task in reportscoll and taskfileslogscoll
            for coll_name in [defaultdb["reportscoll"], defaultdb["taskfileslogscoll"]]:
                coll = CLIENT[db_name][coll_name]
                for doc in coll.find({"task": task_id}):
                    file_id = doc.get("file")
                    if file_id:
                        try:
                            gfs.delete(file_id)
                        except Exception:
                            pass
                try:
                    coll.delete_many({"task": task_id})
                except Exception:
                    pass

            for artifact in CLIENT[db_name][defaultdb['artifactscoll']].find({'task': task_id}):
                gfs.delete(artifact['file'])
            CLIENT[db_name][defaultdb['artifactscoll']].delete_many({'task': task_id})
            CLIENT[db_name][defaultdb['loglinescoll']].delete_many({'task': task_id})

            # 2. Clean up disk output artifacts (logs, screenshots, videos, sockets)
            try:
                if str(UUID(task_id)) != task_id:
                    continue
                task_dir = path.join(output_folder, task_id)
                if path.exists(task_dir) and not path.islink(task_dir):
                    shutil.rmtree(task_dir, ignore_errors=True)
                for suffix in ('-analyzer.logs', '-sniffer.logs'):
                    legacy = path.join(output_folder, task_id + suffix)
                    if path.isfile(legacy) and not path.islink(legacy):
                        __import__('os').unlink(legacy)
            except Exception:
                pass

            # 3. Remove the task record from taskdblogs
            try:
                taskdb_coll.delete_one({"_id": task_doc["_id"]})
                cleaned_count += 1
            except Exception:
                pass

        # 4. Prune global application logs older than cutoff
        try:
            CLIENT[db_name][defaultdb["alllogscoll"]].delete_many({"time": {"$lt": cutoff}})
        except Exception:
            pass

        print(f"[Retention] Successfully cleaned up {cleaned_count} analyses older than {days} days", flush=True)
        return cleaned_count
    except Exception as e:
        print(f"[Retention] Error during analysis cleanup: {e}", flush=True)
        return 0
