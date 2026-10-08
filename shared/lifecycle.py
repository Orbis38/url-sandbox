"""Lifecycle states never schedule retries or restore interrupted sessions."""
TERMINAL = {'completed', 'failed', 'timed_out', 'interrupted', 'cancelled'}


def task_status(item):
    if item.get('status') in TERMINAL | {'running', 'queued'}:
        return item['status']
    if item.get('end'):
        return 'completed'
    return 'running' if item.get('has_logs') or item.get('logs') else 'queued'
