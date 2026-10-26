"""Turn the sandbox's reachability record into analyst-facing text (shared by worker and web)."""


def explain(record):
    '''
    None when the page loaded; otherwise {'title', 'message', 'tor_ok', 'suggest_direct'}
    '''
    if not record or record.get('page_loaded', record.get('reachable', True)):
        return None
    reason = record.get('reason') or 'the page did not load in the browser'
    if record.get('via_tor'):
        if record.get('tor_ok'):
            return {'title': 'The site did not respond through Tor',
                    'message': 'Tor itself is working (the control check through Tor succeeded), but ' + reason +
                               '. The site most likely blocks Tor exit nodes, or is down.',
                    'tor_ok': True, 'suggest_direct': True}
        if 'tor_ok' in record:
            return {'title': 'Tor is not routing traffic',
                    'message': 'The control check through Tor failed too, so the problem is the Tor proxy, '
                               'not the site. Check the proxy container.',
                    'tor_ok': False, 'suggest_direct': False}
    return {'title': 'The site could not be reached',
            'message': reason[0].upper() + reason[1:] + '.',
            'tor_ok': None, 'suggest_direct': False}


def failure_message(record):
    '''
    one line for the task's error field, or None when the page loaded
    '''
    info = explain(record)
    return '{}: {}'.format(info['title'], info['message']) if info else None
