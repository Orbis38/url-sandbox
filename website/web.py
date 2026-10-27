'''
    __G__ = "(G)bd249ce4"
    web interface
'''

import re
from os import environ, path, makedirs
from uuid import UUID, uuid4
from datetime import timedelta, datetime
from json import dumps, loads
from urllib.parse import urlsplit
from bson.objectid import ObjectId
from flask import Flask, flash, g, jsonify, redirect, request, session, url_for, send_file, Response
from flask_mongoengine import MongoEngine
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms import form, fields, validators, SelectMultipleField
from flask_admin import AdminIndexView, Admin, expose, BaseView
from flask_admin.menu import MenuLink
from flask_admin.babel import gettext
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_bcrypt import Bcrypt
from flaskext.markdown import Markdown
from flask_wtf.csrf import CSRFProtect
from pymongo import ASCENDING
from redis import Redis
from celery import Celery
from bs4 import BeautifulSoup
from validator_collection import validators as url_validators
from werkzeug.exceptions import HTTPException, default_exceptions
from shared.settings import defaultdb, json_settings, meta_users_settings
from shared.logger import ignore_exception
from shared.mongodbconn import CLIENT, get_it_fs, ensure_indexes, put_artifact, get_artifact, open_artifact, get_task_logs
from shared.artifacts import ARTIFACT_NAMES, table_field, preview_jpeg
from shared.retention import cleanup_expired_analyses
from shared.apikeys import create_api_key, authenticate_api_key, revoke_api_key
from shared.security import load_session_secret, login_attempt, validate_timeouts
from shared.lifecycle import task_status, TERMINAL
from shared.reachability import explain as explain_reachability

SWITCHES = [
    ('use_proxy', 'use Tor'),
    ('no_redirect', 'no redirect'),
    ('take_screenshot', 'capture screenshot'),
    ('take_full_screenshot', 'full screenshot'),
    ('sniffer_on', 'turn sniffer on'),
    ('interactive', 'interactive mode'),
    ('record_vnc', 'record VNC video'),
    ('block_cookies', 'block cookie popups')
]

SWITCHES_MAPPED = {
    'Chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Chrome (Windows)': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Chrome (macOS)': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Chrome (Linux)': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Safari (macOS)': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
    'Safari (iPhone)': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Chrome (Android)': 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Googlebot (Desktop)': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Googlebot (Smartphone)': 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
}

USERAGENTS = [
    ('Chrome', 'Google Chrome (Windows 10/11 - Default)'),
    ('Chrome (macOS)', 'Google Chrome (macOS)'),
    ('Chrome (Linux)', 'Google Chrome (Linux)'),
    ('Edge', 'Microsoft Edge (Windows 10/11)'),
    ('Firefox', 'Mozilla Firefox (Windows)'),
    ('Safari (macOS)', 'Apple Safari (macOS)'),
    ('Safari (iPhone)', 'Apple Safari (iPhone / iOS Mobile)'),
    ('Chrome (Android)', 'Google Chrome (Android Mobile)'),
    ('Googlebot (Desktop)', 'Googlebot Crawler (Desktop)'),
    ('Googlebot (Smartphone)', 'Googlebot Crawler (Smartphone)')
]

EMAIL_WORKER = json_settings[environ["project_env"]]["email_worker"]
EMAIL_MAX_BYTES = EMAIL_WORKER["max_upload_bytes"]
EMAIL_UPLOAD_PATHS = ('/email/', '/api/v1/analyze/email')
REQUEST_MAX_BYTES = 1024 * 1024

APP = Flask(__name__)
APP.secret_key = load_session_secret()
# Only the email uploads may send more than REQUEST_MAX_BYTES (see limit_request_size).
APP.config['MAX_CONTENT_LENGTH'] = EMAIL_MAX_BYTES + 64 * 1024
APP.config['MONGODB_SETTINGS'] = json_settings[environ["project_env"]]["web_mongo"]
APP.config['SESSION_COOKIE_SAMESITE'] = "Lax"
ANALYZER_TIMEOUT = json_settings[environ["project_env"]]["analyzer_timeout"]
URL_TIMEOUT = json_settings[environ["project_env"]]["url_timeout"]
RD = Redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
CELERY = Celery(json_settings[environ["project_env"]]["celery_settings"]["name"],
                broker=json_settings[environ["project_env"]]["celery_settings"]["celery_broker_url"],
                backend=json_settings[environ["project_env"]]["celery_settings"]["celery_result_backend"])

MONGO_DB = MongoEngine()
MONGO_DB.init_app(APP)
ensure_indexes()
BCRYPT = Bcrypt(APP)
LOGIN_MANAGER = LoginManager()
LOGIN_MANAGER.setup_app(APP)
CSRF = CSRFProtect()
CSRF.init_app(APP)
Markdown(APP)

try:
    cleanup_expired_analyses(days=json_settings[environ["project_env"]].get("retention_days", 60), project_env=environ["project_env"])
except Exception as _ce:
    print(f"Web startup retention check: {_ce}", flush=True)

APP.jinja_env.add_extension('jinja2.ext.loopcontrols')


@LOGIN_MANAGER.user_loader
def load_user(user_id):
    '''
    load user
    '''
    return User.objects(id=user_id).first()


class User(MONGO_DB.Document):
    '''
    this class has all users
    '''
    login = MONGO_DB.StringField(max_length=80, unique=True)
    password = MONGO_DB.StringField(max_length=64)
    meta = meta_users_settings

    @property
    def is_authenticated(self):
        '''
        is the user authenticated or not
        '''
        return True

    @property
    def is_active(self):
        '''
        is the user active or not
        '''
        return True

    @property
    def is_anonymous(self):
        '''
        is the user anonymous (this function not used)
        '''
        return False

    def get_id(self):
        '''
        get user id from the database
        '''
        return str(self.id)

    def __unicode__(self):
        '''
        unicode
        '''
        return self.login


class LoginForm(form.Form):
    '''
    login form (username and password)
    '''
    login = fields.StringField(validators=[validators.InputRequired(), validators.Length(max=80)], render_kw={"placeholder": "Username", "autocomplete": "off"})
    password = fields.PasswordField(validators=[validators.InputRequired()], render_kw={"placeholder": "Password", "autocomplete": "off"})

    def validate_login(self, field):
        '''
        log in
        '''
        if not self.password.data:
            raise validators.ValidationError('Password required')
        user = self.get_user()  # fix AttributeError: 'NoneType' object has no attribute 'password'
        if user is not None:
            if not BCRYPT.check_password_hash(user.password, self.password.data):
                raise validators.ValidationError('Invalid password')

    def get_user(self):
        '''
        get log in
        '''
        return User.objects(login=self.login.data).first()


class RegistrationForm(form.Form):
    '''
    register form (username and password)
    '''
    login = fields.StringField(render_kw={"placeholder": "Username"})
    password = fields.PasswordField(render_kw={"placeholder": "Password"})

    def validate_login(self, field):
        '''
        get log in
        '''
        if User.objects(login=self.login.data):
            raise validators.ValidationError('Duplicate username')


class CustomAdminIndexView(AdminIndexView):
    '''
    Custom login view
    '''
    def is_visible(self):
        '''
        hidden from the sidebar menu, index redirects to the task queue
        '''
        return False

    @expose('/')
    def index(self):
        '''
        main route
        '''
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        # land on the live task queue, mirroring the UrlProbe dashboard flow
        return redirect('/queue/')

    @expose('/login/', methods=['POST', 'GET'])
    def login_view(self):
        '''
        login route
        '''
        temp_form = LoginForm(request.form)
        if request.method == 'POST':
            attempts = CLIENT[defaultdb['dbname']]['login_attempts']
            allowed, retry_after, account_bucket = login_attempt(
                attempts, temp_form.login.data or '', request.remote_addr or 'unknown')
            if not allowed:
                flash(f'Too many login attempts. Try again in {retry_after} seconds.', 'error')
                self._template_args.update(form=temp_form, active='Login', intro='', link='')
                response = APP.make_response(super(CustomAdminIndexView, self).index())
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response
        if request.method == 'POST' and temp_form.validate():
            user = temp_form.get_user()
            if user is not None:
                login_user(user)
                attempts.delete_one({'_id': account_bucket})

        if current_user.is_authenticated:
            session["navs"] = []
            return redirect(request.args.get('next') or url_for('.index'))

        self._template_args['form'] = temp_form
        self._template_args['active'] = "Login"
        self._template_args['intro'] = ""
        self._template_args['link'] = '<p>Register? <a href="{}">Click here</a></p>'.format(url_for('.register_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        '''
        register route
        '''
        temp_form = RegistrationForm(request.form)
        if request.method == 'POST' and temp_form.validate():
            user = User()
            temp_form.populate_obj(user)
            if len(user["password"]) > 0 and len(user["login"]) > 0:
                user["password"] = BCRYPT.generate_password_hash(user["password"]).decode('utf-8')
                user.save()
                login_user(user)
                session["navs"] = []
                return redirect(url_for('.index'))

        self._template_args['form'] = temp_form
        self._template_args['active'] = "Register"
        self._template_args['intro'] = ""
        self._template_args['link'] = '*Please do not enter a used username or password<p><p>Login? <a href="{}">Click here</a></p>'.format(url_for('.login_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        '''
        logout route
        '''
        logout_user()
        session["navs"] = []
        return redirect(url_for('.index'))

    @expose('/toggled', methods=('GET', 'POST'))
    def is_toggled(self):
        '''
        toggled route (this will keep track of toggled items)
        '''
        with ignore_exception(Exception):
            if current_user.is_authenticated:
                json_content = request.get_json(silent=True)
                for key, value in json_content.items():
                    if value == "false":
                        session["navs"].remove(key)
                    else:
                        session["navs"].append(key)
        return jsonify("Done")

    def is_visible(self):
        '''
        Do not show items in the sidebar
        '''
        return False


class MultiCheckboxField(SelectMultipleField):
    '''
    this class will be used for mulit checckbox
    '''
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()


class BufferForm(form.Form):
    '''
    needs more check
    '''
    choices = MultiCheckboxField('Assigned', choices=SWITCHES, default=['use_proxy', 'take_screenshot', 'block_cookies'])
    buffer = fields.TextAreaField(render_kw={"class": "buffer"})
    useragents = fields.SelectField('useragents', choices=USERAGENTS, default="Chrome")
    urltimeout = fields.SelectField('urltimeout', choices=[(5, '5 sec URL timeout'), (10, '10 sec URL timeout'), (30, '30 sec URL timeout'), (60, '1 min URL timeout')], default=(URL_TIMEOUT), coerce=int)
    analyzertimeout = fields.SelectField('analyzertimeout', choices=[(30, '30 sec analyzing timeout'), (60, '1 min analyzing timeout'), (120, '2 mins analyzing timeout')], default=(ANALYZER_TIMEOUT), coerce=int)
    interactivetimeout = fields.SelectField('interactivetimeout', choices=[(300, '5 min interactive timeout'), (600, '10 min interactive timeout'), (900, '15 min interactive timeout')], default=300, coerce=int)
    submit = fields.SubmitField('Analyze', render_kw={"class": "up-btn up-btn-primary up-btn-lg"})
    submitandwait = fields.SubmitField('Analyze & Wait', render_kw={"class": "up-btn up-btn-secondary up-btn-lg"})
    __order = ('buffer', 'choices', 'useragents', 'urltimeout', 'analyzertimeout', 'interactivetimeout', 'submit', 'submitandwait')

    def __iter__(self):
        temp_fields = list(super(BufferForm, self).__iter__())
        def get_field(fid): return next((f for f in temp_fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)


class CustomViewBufferForm(BaseView):
    '''
    upload buffer main form
    '''
    def is_visible(self):
        '''
        hidden from the sidebar menu, reachable via the New Analysis buttons
        '''
        return False

    @expose('/', methods=['POST', 'GET'])
    def index(self):
        '''
        main route
        '''
        # GET gets no formdata so the default switches (Tor, screenshot, cookies) show as on
        temp_form = BufferForm(request.form if request.method == 'POST' else None)
        if request.method == 'POST':
            if not temp_form.validate():
                flash('Invalid analysis options.', 'error')
                return self.render('upload.html', header='New Analysis', form=temp_form, switches_details='',
                                   recent=get_queue_tasks(limit=3)), 400
            target, scheme_fallback = normalize_target(temp_form.buffer.data)
            if target != "":
                good_url = False
                try:
                    url_validators.url(target)
                    good_url = True
                except BaseException:
                    pass
                if good_url:
                    task = str(uuid4())
                    result = {}
                    for item in SWITCHES:
                        result.update({item[0]: False})
                    for item in request.form.getlist("choices"):
                        result.update({item: True})
                    result["buffer"] = target
                    result["scheme_fallback"] = scheme_fallback
                    result["proxy"] = 'socks5://proxy:9050' if result.get('use_proxy') else ''
                    result["task"] = task
                    result["owner_id"] = str(current_user.get_id())
                    result["analyzer_timeout"] = temp_form.analyzertimeout.data
                    result["url_timeout"] = temp_form.urltimeout.data
                    result["interactive_timeout"] = temp_form.interactivetimeout.data
                    result["useragent"] = temp_form.useragents.data
                    result["useragent_mapped"] = SWITCHES_MAPPED[temp_form.useragents.data]
                    parent = owned_task(request.form.get('parent_task'))
                    if parent and parent.get('type') == 'email':
                        # a link opened from an email report is listed back on that report
                        result["parent_task"] = parent['task']
                    enqueue_owned_task(result)
                    if request.form.get('submitandwait') == 'Analyze & Wait':
                        # open the task's report page; it waits and reloads when the task ends
                        return redirect('/report/' + task)
                    # plain submit — jump straight to the live task queue
                    flash(gettext('Analysis queued'), 'success')
                    return redirect('/queue/')
                else:
                    flash(gettext("Invalid URL"), 'error')
            else:
                flash(gettext("Something wrong"), 'error')
        return self.render("upload.html", header="New Analysis", form=temp_form, switches_details="",
                           recent=get_queue_tasks(limit=3))

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))


OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
HEADER_LINE = re.compile(rb'^[!-9;-~]+:[ \t]', re.MULTILINE)
MAIL_HEADERS = re.compile(rb'^(from|subject|date|received|message-id|to|return-path|mime-version):', re.IGNORECASE | re.MULTILINE)


def email_input_name(raw):
    '''input.msg for an Outlook file, input.eml for an RFC 822 message, None for anything else'''
    if raw.startswith(OLE_MAGIC):
        return 'input.msg'
    head = raw[:64 * 1024].lstrip(b'\xef\xbb\xbf\r\n\t ')
    if head.startswith(b'From '):
        head = head.split(b'\n', 1)[-1]  # mbox separator line
    first = head.split(b'\n', 1)[0]
    if HEADER_LINE.match(first) and MAIL_HEADERS.search(head.split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0]):
        return 'input.eml'
    return None


def display_filename(name):
    name = path.basename(str(name or '').replace('\\', '/'))
    name = ''.join(ch for ch in name if ch.isprintable() and ch not in '\u202e\u202d')
    return name[:200] or 'message'


def queue_email(upload, owner_id):
    '''store an uploaded .eml/.msg in its task folder and queue it; returns (task id, error)'''
    if upload is None:
        return None, 'Choose an .eml or .msg file'
    raw = upload.read(EMAIL_MAX_BYTES + 1)
    if not raw:
        return None, 'The file is empty'
    if len(raw) > EMAIL_MAX_BYTES:
        return None, 'The file is larger than {} MB'.format(EMAIL_MAX_BYTES // (1024 * 1024))
    input_name = email_input_name(raw)
    if not input_name:
        return None, 'This is not an .eml or .msg email message'
    task = str(uuid4())
    task_dir = path.join(json_settings[environ["project_env"]]["output_folder"], task)
    makedirs(task_dir, exist_ok=True)
    with open(path.join(task_dir, input_name), 'wb') as handle:
        handle.write(raw)
    filename = display_filename(upload.filename)
    enqueue_owned_task({'task': task, 'owner_id': owner_id, 'type': 'email', 'buffer': filename,
                        'filename': filename, 'input_name': input_name, 'size': len(raw)}, 'email_worker')
    return task, None


class CustomViewEmailForm(BaseView):
    '''
    upload an email (.eml / .msg) for analysis
    '''
    def is_visible(self):
        return False

    @expose('/', methods=['POST', 'GET'])
    def index(self):
        if request.method == 'POST':
            task, error = queue_email(request.files.get('file'), str(current_user.get_id()))
            if error:
                flash(error, 'error')
                return self.render('upload_email.html', header='New Analysis', max_mb=EMAIL_MAX_BYTES // (1024 * 1024),
                                   recent=get_queue_tasks(limit=3)), 400
            if request.form.get('submitandwait'):
                return redirect('/report/' + task)
            flash(gettext('Analysis queued'), 'success')
            return redirect('/queue/')
        return self.render('upload_email.html', header='New Analysis', max_mb=EMAIL_MAX_BYTES // (1024 * 1024),
                           recent=get_queue_tasks(limit=3))

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login_view', next=request.url))


def _relative_time(dt):
    '''
    humanize a UTC datetime as a short "x ago" string
    '''
    if not dt:
        return "—"
    delta = datetime.utcnow() - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0
    if secs < 60:
        return "just now"
    if secs < 3600:
        return "{}m ago".format(secs // 60)
    if secs < 86400:
        return "{}h ago".format(secs // 3600)
    return "{}d ago".format(secs // 86400)


def _format_duration(start, end):
    '''
    format elapsed time between start and end (or now while running)
    '''
    if not start:
        return "—"
    ref = end or datetime.utcnow()
    secs = int((ref - start).total_seconds())
    if secs < 0:
        secs = 0
    if secs < 60:
        return "{}s".format(secs)
    return "{}m {:02d}s".format(secs // 60, secs % 60)


STATUS_LABELS = {
    'queued': 'Queued', 'running': 'Running', 'completed': 'Completed', 'failed': 'Failed',
    'timed_out': 'Timed out', 'interrupted': 'Interrupted', 'cancelled': 'Cancelled'
}
PROBLEM_STATES = {'failed', 'timed_out', 'interrupted', 'cancelled'}


SCHEME_PATTERN = re.compile(r'^[a-z][a-z0-9+.-]*://', re.IGNORECASE)


def normalize_target(raw):
    '''
    accept targets typed without a scheme: assume https:// and flag it, so the
    sandbox may fall back to http:// when the https attempt fails
    '''
    url = (raw or '').strip()
    if url and not SCHEME_PATTERN.match(url):
        return 'https://' + url.lstrip('/'), True
    return url, False


def split_target(target):
    '''
    split a target URL into host and the rest, scheme dropped, for compact display
    '''
    target = str(target or '')
    with ignore_exception(Exception):
        parts = urlsplit(target if '://' in target else '//' + target)
        if parts.netloc:
            rest = parts.path + ('?' + parts.query if parts.query else '')
            return parts.netloc, rest
    return target, ''


VNC_LABELS = {'active': 'Active', 'starting': 'Starting', 'inactive': 'Inactive', 'none': 'Not requested'}


def socket_listening(socket_path):
    '''
    is a sandbox still serving this control socket? The file outlives a box that was removed
    from outside (run.sh restart, docker rm -f), so only an accepted connection counts. The box
    drops an empty connection at once and it does not reset the session's idle timer.
    '''
    import socket
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(socket_path)
        return True
    except OSError:
        return False
    finally:
        probe.close()


def read_vnc_session(task_id):
    '''
    live-session files the box writes into the task's output folder: saved metadata and
    whether its control socket still answers
    '''
    import json
    output_dir = path.join(json_settings[environ["project_env"]]["output_folder"], task_id)
    saved = {}
    with ignore_exception(Exception):
        with open(path.join(output_dir, "vnc_session.json")) as handle:
            saved = json.load(handle)
    socket_file = path.join(output_dir, "control.sock")
    socket_alive = path.exists(socket_file) and saved.get("status") != "ended" and socket_listening(socket_file)
    return saved, socket_alive, socket_alive, output_dir


def vnc_state(task_id, interactive, status):
    '''
    none (not requested), starting (requested, session not up yet), active, inactive (ended)
    '''
    if not interactive:
        return 'none'
    saved, socket_alive, active, _ = read_vnc_session(task_id)
    if active:
        return 'active'
    if status in ('queued', 'running') and not saved and not socket_alive:
        return 'starting'
    return 'inactive'


def get_queue_tasks(limit=100):
    '''
    live task queue built from the task lifecycle collection (taskdblogs).
    end is None while a task is queued/running, set once it completes.
    '''
    tasks = []
    owner_id = request_owner_id()
    if not owner_id:
        return tasks
    with ignore_exception(Exception):
        cursor = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find(
            {"owner_id": owner_id}, {'task': 1, 'buffer': 1, 'domain': 1, 'type': 1, 'interactive': 1,
                                     'start': 1, 'end': 1, 'status': 1, 'has_logs': 1, 'logs': {'$slice': 1},
                                     'subject': 1, 'filename': 1}
        ).sort([("start", -1)]).limit(limit)
        for item in cursor:
            start = item.get("start")
            end = item.get("end")
            logs = item.get("logs") or []
            status = task_status(item)
            if item.get("type") == "email":
                # subject once parsed, the uploaded file name until then
                target = item.get("subject") or item.get("filename") or "(no subject)"
                host, rest = target, ""
            else:
                target = item.get("buffer", "") or item.get("domain", "") or "—"
                host, rest = split_target(target)
            tasks.append({
                "task": item.get("task", ""),
                "short": item.get("task", "")[:8],
                "target": target,
                "host": host,
                "rest": rest,
                "type": {"file": "File", "email": "Email"}.get(item.get("type"), "URL"),
                "status": status,
                "status_label": STATUS_LABELS.get(status, status.replace('_', ' ').capitalize()),
                "vnc": vnc_state(item.get("task", ""), item.get("interactive"), status),
                "submitted": _relative_time(start),
                "duration": _format_duration(start, end),
            })
    return tasks


def get_queue_kpis(tasks):
    '''
    summary counters for the queue KPI row
    '''
    return {
        "total": len(tasks),
        "running": sum(1 for t in tasks if t["status"] == "running"),
        "queued": sum(1 for t in tasks if t["status"] == "queued"),
        "completed": sum(1 for t in tasks if t["status"] in TERMINAL),
        "failed": sum(1 for t in tasks if t["status"] in PROBLEM_STATES),
    }


class CustomQueueView(BaseView):
    '''
    live task queue view (auto-refreshing)
    '''
    extra_js = ['/static/queue.js']

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        '''
        GET renders the queue shell, POST returns the current queue as JSON
        '''
        if request.method == 'POST':
            tasks = get_queue_tasks()
            return jsonify({"tasks": tasks, "kpis": get_queue_kpis(tasks)})
        tasks = get_queue_tasks()
        return self.render("queue.html", tasks=tasks, kpis=get_queue_kpis(tasks))

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))


def _as_text(value):
    '''
    certificate fields arrive as strings, lists of strings or lists of single-key dicts
    '''
    if isinstance(value, (list, tuple)):
        items = [list(x.values())[0] if isinstance(x, dict) and x else x for x in value]
        return ', '.join(str(x) for x in items if x not in (None, ''))
    return str(value or '')


def load_report_summary(task_id):
    '''
    the structured summary qbreport stores next to the HTML report (empty dict if absent)
    '''
    with ignore_exception(Exception):
        raw = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json; type=ai_summary"})
        if raw:
            return loads(raw.decode('utf-8', 'ignore') if isinstance(raw, bytes) else raw)
    return {}


def report_run_details(task_id):
    '''
    header and side-rail facts for the report page: status, timing, options, summary
    '''
    doc = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find_one(
        {"task": task_id, "owner_id": request_owner_id()}, {"logs": 0}) or {}
    status = task_status(doc) if doc else 'completed'
    start, end = doc.get("start"), doc.get("end")
    summary = load_report_summary(task_id)
    url_info = summary.get("url_analysis", {}) or {}
    page = summary.get("page_content", {}) or {}
    cert = summary.get("ssl_certificate", {}) or {}
    target = doc.get("buffer") or url_info.get("submitted_url") or doc.get("domain") or task_id
    return {
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "target": target,
        "started": start.strftime('%d %b %Y, %H:%M UTC') if start else '',
        "duration": _format_duration(start, end) if start else '',
        "elapsed_seconds": max(0, int(((end or datetime.utcnow()) - start).total_seconds())) if start else 0,
        "error": doc.get("error") if status in PROBLEM_STATES else '',
        "has_summary": bool(summary),
        "final_url": url_info.get("final_url") or '',
        "redirected": bool(url_info.get("redirected")),
        "final_domain": url_info.get("final_domain") or '',
        "page_title": page.get("page_title") or '',
        "cert_issuer": _as_text(cert.get("issuer")),
        "cert_until": _as_text(cert.get("valid_until")),
        "cert_expired": bool(cert.get("expired")),
        "dns_count": len(summary.get("dns_records") or []),
        "indicators": [str(x).replace('_', ' ') for x in (summary.get("threat_indicators") or [])],
        "options": [(label, bool(doc.get(key))) for key, label in REPORT_OPTION_LABELS],
        "useragent": doc.get("useragent") or '',
        "timeouts": [doc.get("url_timeout"), doc.get("analyzer_timeout")],
        "proxy": bool(doc.get("use_proxy")),
        "unreachable": explain_reachability(summary.get("reachability")),
        "unreachable_detail": (summary.get("reachability") or {}).get("detail", ''),
        "retry": retry_without_tor(doc),
    }


def _choice(value, field, fallback):
    allowed = [value for value, _ in BufferForm.__dict__[field].kwargs['choices']]
    return value if value in allowed else fallback


def retry_without_tor(doc):
    '''
    the same analysis as a New Analysis form submission, minus Tor (the analyst decides:
    without Tor the target sees the sandbox's public IP)
    '''
    if not doc or not doc.get("use_proxy"):
        return None
    target = doc.get("buffer") or ''
    if doc.get("scheme_fallback") and target.startswith('https://'):
        target = target[len('https://'):]  # keep the https-then-http behaviour of the original
    return {
        "buffer": target,
        "choices": [key for key, _ in SWITCHES if key != 'use_proxy' and doc.get(key)],
        "useragents": doc.get("useragent") if doc.get("useragent") in SWITCHES_MAPPED else 'Chrome',
        "urltimeout": _choice(doc.get("url_timeout"), 'urltimeout', URL_TIMEOUT),
        "analyzertimeout": _choice(doc.get("analyzer_timeout"), 'analyzertimeout', ANALYZER_TIMEOUT),
        "interactivetimeout": _choice(doc.get("interactive_timeout"), 'interactivetimeout', 300),
    }


REPORT_OPTION_LABELS = [
    ('take_screenshot', 'Viewport screenshot'),
    ('take_full_screenshot', 'Full-page screenshot'),
    ('sniffer_on', 'Packet capture'),
    ('block_cookies', 'Cookie banners dismissed'),
    ('interactive', 'Live browser session'),
    ('record_vnc', 'Session recording'),
]


class CustomReportView(BaseView):
    '''
    per-task report viewer (HTML and JSON), reached from the task queue
    '''
    def is_visible(self):
        '''
        hidden from the sidebar, opened from a queue row
        '''
        return False

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index(self):
        return redirect('/queue/')

    @expose('/<task_id>')
    def view(self, task_id):
        '''
        render the stored HTML report body inside the themed layout
        '''
        doc = owned_task(task_id)
        if doc and doc.get('type') == 'email':
            return self.render("email_report.html", task_id=task_id, **email_report_context(task_id))
        body = ""
        with ignore_exception(Exception):
            item = get_it_fs(defaultdb["dbname"], {"task": task_id, 'contentType': 'text/html'})
            if item:
                found = BeautifulSoup(item, 'html.parser').find('body')
                body = found.decode_contents() if found else item.decode('utf-8', 'ignore')
        return self.render("report.html", task_id=task_id, report_body=body, run=report_run_details(task_id))

    @expose('/<task_id>/json')
    def view_json(self, task_id):
        '''
        return the stored JSON report as a downloadable/inline document
        '''
        item = None
        with ignore_exception(Exception):
            item = get_it_fs(defaultdb["dbname"], {"task": task_id, 'contentType': 'application/json'})
        if not item:
            return jsonify(error="No JSON report for this task"), 404
        if isinstance(item, bytes):
            item = item.decode('utf-8', 'ignore')
        return APP.response_class(item, mimetype='application/json')

    @expose('/<task_id>/message')
    def view_message(self, task_id):
        '''
        the email body as rendered by the mailbox container, for the report's sandboxed iframe
        '''
        artifact = get_artifact(defaultdb['dbname'], task_id, 'email_message')
        if not artifact:
            return jsonify(error='No rendered message for this task'), 404
        return inert_html_response(artifact[0])

    @expose('/<task_id>/rendered/<digest>')
    def view_rendered_attachment(self, task_id, digest):
        '''
        an HTML/SVG attachment, rendered as inert as the message body
        '''
        source = mail_output_file(task_id, 'rendered', digest, '.html')
        if not source:
            return jsonify(error='No rendering for this attachment'), 404
        with open(source, 'rb') as handle:
            return inert_html_response(handle.read())

    @expose('/<task_id>/samples/<sample>.zip')
    def download_sample(self, task_id, sample):
        '''
        one attachment (or all.zip with every one) as a ZIP encrypted with the password "infected"
        '''
        # (flask-admin reserves the view argument "name")
        source = mail_output_file(task_id, 'samples', sample, '.zip')
        if not source:
            return jsonify(error='No such attachment'), 404
        download = 'attachments-{}.zip'.format(task_id[:8]) if sample == 'all' else '{}.zip'.format(sample[:16])
        response = send_file(source, mimetype='application/zip', as_attachment=True, download_name=download)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @expose('/<task_id>/original')
    def download_original(self, task_id):
        '''
        the uploaded message file, always as a download (never rendered by the browser)
        '''
        doc = owned_task(task_id)
        input_name = doc.get('input_name') if doc else None
        if input_name not in ('input.eml', 'input.msg'):
            return jsonify(error='No original message for this task'), 404
        source = path.join(json_settings[environ["project_env"]]["output_folder"], task_id, input_name)
        if not path.isfile(source) or path.islink(source):
            return jsonify(error='The original message is no longer stored'), 404
        name = display_filename(doc.get('filename'))
        extension = input_name.rsplit('.', 1)[1]
        if not name.lower().endswith('.' + extension):
            name += '.' + extension
        response = send_file(source, mimetype='application/octet-stream', as_attachment=True, download_name=name)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @expose('/<task_id>/iocs.csv')
    def download_iocs(self, task_id):
        '''
        the indicators of compromise of an email analysis as type,value rows
        '''
        analysis = load_email_analysis(task_id)
        if not analysis:
            return jsonify(error='No email analysis for this task'), 404
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['type', 'value'])
        for kind, values in (analysis.get('iocs') or {}).items():
            for value in values:
                # a leading = + - @ would make spreadsheets evaluate the cell
                text = str(value)
                writer.writerow([kind, "'" + text if text[:1] in ('=', '+', '-', '@') else text])
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename="iocs-{}.csv"'.format(task_id[:8])
        return response


SHA256_NAME = re.compile(r'^[0-9a-f]{64}$')


def mail_output_file(task_id, folder, name, suffix):
    '''a file the mailbox container wrote for this task, by sha256 (or "all"); None if absent'''
    if not (SHA256_NAME.match(name) or (folder == 'samples' and name == 'all')):
        return None
    source = path.join(json_settings[environ["project_env"]]["output_folder"], task_id, 'mail', folder, name + suffix)
    if not path.isfile(source) or path.islink(source):
        return None
    return source


def inert_html_response(payload):
    response = Response(payload, mimetype='text/html')
    # Defence in depth on top of the mailbox sanitizer and the iframe sandbox: nothing in
    # the message may run or fetch, and only this application may frame it.
    response.headers['Content-Security-Policy'] = MESSAGE_CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cache-Control'] = 'private, no-store'
    return response


MESSAGE_CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; "
               "script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'")

SEVERITY_LABELS = {'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info'}
VERDICT_LABELS = {'suspicious': 'Suspicious', 'review': 'Needs review', 'low': 'Low risk', 'clean': 'No findings'}
LINK_FLAG_LABELS = {
    'masked': 'masked', 'wrapped': 'gateway-wrapped', 'script_scheme': 'script URL', 'ip_host': 'IP address',
    'punycode': 'punycode', 'shortener': 'shortener', 'not_https': 'http', 'credentials_in_url': 'user@host',
    'file_scheme': 'file URL', 'malformed': 'malformed'}
ATTACHMENT_FLAG_LABELS = {
    'executable': 'executable', 'macro_enabled': 'macro-enabled', 'contains_macros': 'contains macros',
    'legacy_office': 'legacy Office', 'html': 'HTML', 'archive': 'archive', 'encrypted_archive': 'encrypted',
    'double_extension': 'double extension', 'rtlo_filename': 'RTL override', 'type_mismatch': 'type mismatch',
    'disk_image': 'disk image', 'onenote': 'OneNote'}
RISKY_FLAGS = {'masked', 'script_scheme', 'ip_host', 'punycode', 'credentials_in_url', 'file_scheme', 'executable',
               'macro_enabled', 'contains_macros', 'encrypted_archive', 'double_extension', 'rtlo_filename',
               'type_mismatch', 'disk_image', 'onenote', 'html'}


def load_email_analysis(task_id):
    '''
    the analysis the mailbox container produced (empty dict while queued or if parsing failed)
    '''
    with ignore_exception(Exception):
        raw = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json"})
        if raw:
            return loads(raw.decode('utf-8', 'ignore') if isinstance(raw, bytes) else raw)
    return {}


def email_report_context(task_id):
    '''
    everything the email report template needs: run facts, the analysis and child URL analyses
    '''
    owner_id = request_owner_id()
    collection = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]]
    doc = collection.find_one({"task": task_id, "owner_id": owner_id}, {"logs": 0}) or {}
    status = task_status(doc) if doc else 'completed'
    start, end = doc.get("start"), doc.get("end")
    analysis = load_email_analysis(task_id)
    message = analysis.get('message') or {}
    children = {}
    for child in collection.find({"parent_task": task_id, "owner_id": owner_id},
                                 {"task": 1, "buffer": 1, "status": 1, "end": 1, "has_logs": 1, "logs": {'$slice': 1}}
                                 ).sort([("start", 1)]):
        state = task_status(child)
        children[child.get("buffer", "")] = {"task": child["task"], "status": state,
                                             "status_label": STATUS_LABELS.get(state, state)}
    return {
        "run": {
            "status": status,
            "status_label": STATUS_LABELS.get(status, status),
            "target": message.get('subject') or doc.get('subject') or doc.get('filename') or task_id,
            "filename": doc.get('filename') or analysis.get('filename') or '',
            "started": start.strftime('%d %b %Y, %H:%M UTC') if start else '',
            "duration": _format_duration(start, end) if start else '',
            "elapsed_seconds": max(0, int(((end or datetime.utcnow()) - start).total_seconds())) if start else 0,
            "error": doc.get("error") if status in PROBLEM_STATES else '',
        },
        "mail": analysis,
        "children": children,
        "severity_labels": SEVERITY_LABELS,
        "verdict_labels": VERDICT_LABELS,
        "link_flag_labels": LINK_FLAG_LABELS,
        "attachment_flag_labels": ATTACHMENT_FLAG_LABELS,
        "risky_flags": RISKY_FLAGS,
        "url_defaults": {"urltimeout": URL_TIMEOUT, "analyzertimeout": ANALYZER_TIMEOUT},
    }


def email_summary(task_id, analysis):
    '''
    compact, SOAR-friendly view of an email analysis
    '''
    return {
        "task_id": task_id,
        "status": "completed",
        "type": "email",
        "verdict": analysis.get("verdict"),
        "message": analysis.get("message"),
        "authentication": {key: (analysis.get("authentication") or {}).get(key) for key in ("spf", "dkim", "dmarc")},
        "indicators": [{key: item.get(key) for key in ("id", "severity", "title", "detail")}
                       for item in analysis.get("indicators") or []],
        "links": [{key: item.get(key) for key in ("url", "target", "display", "domain", "flags")}
                  for item in analysis.get("links") or []],
        "attachments": [{key: item.get(key) for key in ("filename", "size", "detected", "sha256", "flags")}
                        for item in analysis.get("attachments") or []],
        "iocs": analysis.get("iocs") or {},
        "file": {"filename": analysis.get("filename"), "format": analysis.get("format"),
                 "sha256": (analysis.get("hashes") or {}).get("sha256")},
    }


class CustomTaskLogView(BaseView):
    '''
    per-task log viewer, reached from the task queue
    '''
    def is_visible(self):
        return False

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index(self):
        return redirect('/queue/')

    @expose('/<task_id>')
    def view(self, task_id):
        '''
        show the log lines captured for a single task
        '''
        target = task_id
        logs = []
        with ignore_exception(Exception):
            item = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find_one({"task": task_id})
            if item:
                target = item.get("buffer") or item.get("domain") or task_id
                logs = get_task_logs(defaultdb['dbname'], task_id, request_owner_id(), item.get('logs') or [])
        return self.render("tasklog.html", task_id=task_id, target=target, logs=logs)


def find_and_srot(database, collection, key, var):
    '''
    hmm finding by time is weird?
    '''
    temp_list = []
    if key == "time":
        items = list(CLIENT[database][collection].find().sort([('_id', -1)]).limit(1))
    else:
        items = list(CLIENT[database][collection].find({key: {"$gt": var}}).sort([(key, ASCENDING)]))
    for item in items:
        temp_list.append("{} {}".format(item["time"].isoformat(), item["message"]))
    if len(temp_list) > 0:
        return "\n".join(temp_list), str(items[-1]["_id"])
    return "", 0


def get_last_logs(json):
    '''
    get last item from logs
    '''
    owner_id = request_owner_id()
    if not owner_id:
        return {'id': 0, 'logs': ''}
    cursor = json.get('id', 0)
    initial = cursor in (0, '0', 'legacy')
    query = {'owner_id': owner_id}
    if not initial:
        try:
            query['_id'] = {'$gt': ObjectId(cursor)}
        except Exception:
            raise ValueError('Invalid log cursor')
    collection = CLIENT[defaultdb['dbname']][defaultdb['loglinescoll']]
    records = list(collection.find(query, {'message': 1}).sort('_id', -1 if initial else 1).limit(201))
    more = len(records) > 200 and not initial
    if initial:
        records = list(reversed(records[:200]))
    else:
        records = records[:200]
    if records:
        return {'id': str(records[-1]['_id']), 'logs': '\n'.join(row['message'] for row in records),
                'reset': cursor in (0, '0'), 'has_more': more}
    if cursor in (0, '0'):
        # A bounded snapshot preserves access to old embedded logs, once per page.
        docs = list(CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']].find(
            {'owner_id': owner_id}, {'task': 1, 'start': 1, 'logs': {'$slice': -20}}).sort('start', -1).limit(10))
        lines = [line for doc in reversed(docs) for line in (doc.get('logs') or [])][-200:]
        return {'id': 'legacy', 'logs': '\n'.join(lines), 'reset': True, 'has_more': False}
    return {'id': cursor, 'logs': '', 'reset': False, 'has_more': False}


class CustomLogsView(BaseView):
    '''
    logs view
    '''
    extra_js = ['/static/activelogs.js']

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        '''
        main entry
        '''
        if request.method == 'GET':
            return self.render("activelogs.html")
        elif request.method == 'POST':
            if request.json:
                json_content = request.get_json(silent=True)
                try:
                    return jsonify(get_last_logs(json_content))
                except (ValueError, AttributeError):
                    return jsonify(error='Invalid log cursor'), 400
        return jsonify({"Error": "Something wrong"})

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))


class CheckTask(BaseView):
    '''
    check task view (This acts as api)
    '''
    @expose('/', methods=['POST', 'GET'])
    def index(self):
        '''
        check task route
        '''
        if request.method == 'POST':
            if request.json:
                json_content = request.get_json(silent=True)
                task_id = json_content.get('task') if isinstance(json_content, dict) else None
                item = owned_task(task_id)
                if not item:
                    return jsonify(error="Task not found"), 404
                if item:
                    if item["end"]:
                        item = get_it_fs(defaultdb["dbname"], {"task": json_content["task"], 'contentType': 'text/html'})
                        if item:
                            return BeautifulSoup(item).find('body').decode_contents()
                        return "Something wrong"
            return ""
        return self.render("activelogs.html")

    def is_visible(self):
        '''
        not visable in the bar (just an api)
        '''
        return False

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))


def update_gridfs_report(task_id, new_screenshot_base64, new_full_screenshot_base64=None):
    try:
        from base64 import b64decode
        payload = b64decode(new_screenshot_base64, validate=True)
        put_artifact(defaultdb['dbname'], task_id, 'normal_image', payload, 'image/png')
        try:
            put_artifact(defaultdb['dbname'], task_id, 'ai_image_jpeg', preview_jpeg(payload), 'image/jpeg')
        except Exception:
            pass
        if new_full_screenshot_base64:
            put_artifact(defaultdb['dbname'], task_id, 'full_image',
                         b64decode(new_full_screenshot_base64, validate=True), 'image/png')
        # New reports already reference these endpoints; do not parse/rewrite HTML.
        collection = CLIENT[defaultdb['dbname']][defaultdb['reportscoll']]
        report = collection.find_one({'task': task_id, 'type': 'text/html'},
                                     {'file': 1, 'artifact_references': 1})
        if report and not report.get('artifact_references'):
            # Convert an old inline report once, then future updates only replace binaries.
            html = get_it_fs(defaultdb['dbname'], {'_id': report['file']})
            soup = BeautifulSoup(html, 'html.parser')
            for css, kind in [('table-Screenshot', 'normal_image'), ('table-Full_Screenshot', 'full_image')]:
                table = soup.find('tbody', class_=css)
                image = table.find('img', class_='fullsize') if table else None
                if image and (kind == 'normal_image' or new_full_screenshot_base64):
                    image['src'] = f'/api/v1/tasks/{task_id}/images/{kind}'
            from gridfs import GridFS
            fs = GridFS(CLIENT[defaultdb['dbname']])
            file_id = fs.put(str(soup).encode(), task=task_id, content_type='text/html')
            collection.update_one({'_id': report['_id']}, {'$set': {
                'file': file_id, 'artifact_references': True}})
            fs.delete(report['file'])
    except Exception as e:
        print(f"Error updating GridFS report: {e}", flush=True)


@APP.route('/live_interact/<task_id>', methods=['POST'])
@CSRF.exempt
def live_interact(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized"), 401
        
    json_content = request.get_json(silent=True) or {}
    
    socket_path = path.join(json_settings[environ["project_env"]]["output_folder"], task_id, "control.sock")
    if not path.exists(socket_path):
        return jsonify(error="Session not active or socket not found"), 404
        
    import socket
    import json
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(socket_path)
        client.sendall(json.dumps(json_content).encode('utf-8'))
        
        response_chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response_chunks.append(chunk)
        client.close()
        
        res = json.loads(b''.join(response_chunks).decode('utf-8'))
        if res.get('status') == 'ok':
            new_screenshot = res.get('screenshot')
            new_full_screenshot = res.get('full_screenshot')
            if new_screenshot:
                update_gridfs_report(task_id, new_screenshot, new_full_screenshot)

            if json_content.get('action') == 'close':
                try:
                    output_dir = path.join(json_settings[environ["project_env"]]["output_folder"], task_id)
                    session_path = path.join(output_dir, "vnc_session.json")
                    video_path = path.join(output_dir, "session.mp4")
                    has_vid = path.exists(video_path) and path.getsize(video_path) > 1000
                    sdata = {"task": task_id}
                    if path.exists(session_path):
                        with open(session_path, 'r') as sf:
                            sdata = json.load(sf)
                    sdata["status"] = "ended"
                    sdata["has_video"] = has_vid
                    with open(session_path, 'w') as sf:
                        json.dump(sdata, sf)

                    v_port = sdata.get("vnc_port")
                    if v_port:
                        try:
                            import redis
                            rd = redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
                            rd.srem("active_vnc_ports", v_port)
                        except Exception:
                            pass
                except Exception:
                    pass

            return jsonify(res)
        else:
            return jsonify(error=res.get('message', 'Error from sandbox')), 500
    except Exception as e:
        return jsonify(error=f"Connection error: {str(e)}"), 500


@APP.route('/live_interact/<task_id>/status', methods=['GET'])
@CSRF.exempt
def live_interact_status(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized"), 401
    
    saved, _, is_active, output_dir = read_vnc_session(task_id)
    video_path = path.join(output_dir, "session.mp4")
    has_video = (not is_active) and path.exists(video_path) and path.getsize(video_path) > 1000

    data = {
        "task": task_id,
        "active": is_active,
        "status": "active" if is_active else "ended",
        "vnc_port": saved.get("vnc_port"),
        "vnc_token": saved.get("vnc_token") if is_active else None,
        "record_vnc": saved.get("record_vnc", False),
        "has_video": has_video,
        "video_url": f"/api/v1/tasks/{task_id}/video" if has_video else None
    }

    return jsonify(data)


@APP.route('/api/v1/tasks/<task_id>/video', methods=['GET'])
@CSRF.exempt
def get_task_video(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized"), 401
    video_path = path.join(json_settings[environ["project_env"]]["output_folder"], task_id, "session.mp4")
    if not path.exists(video_path):
        return jsonify(error="No video recording found for this task"), 404
    return send_file(video_path, mimetype='video/mp4')






def api_key_collection():
    return CLIENT[defaultdb['dbname']]['api_keys']


def request_owner_id():
    if hasattr(g, 'owner_id'):
        return g.owner_id
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")
    if 'X-API-Key' in request.headers or 'Authorization' in request.headers:
        token = api_key_header.strip() if api_key_header else (
            auth_header[7:].strip() if auth_header.startswith('Bearer ') else '')
        owner_id = authenticate_api_key(api_key_collection(), token)
        if owner_id and not User.objects(id=owner_id).first():
            owner_id = None
    else:
        owner_id = str(current_user.get_id()) if current_user.is_authenticated else None
    g.owner_id = owner_id
    return owner_id


def check_api_auth():
    return request_owner_id() is not None


def owned_task(task_id):
    owner_id = request_owner_id()
    if not owner_id or not isinstance(task_id, str):
        return None
    try:
        if str(UUID(task_id)) != task_id:
            return None
    except (ValueError, AttributeError):
        return None
    if getattr(g, 'task_doc', {}).get('task') == task_id:
        return g.task_doc
    item = CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']].find_one(
        {'task': task_id, 'owner_id': owner_id},
        {'task': 1, 'owner_id': 1, 'start': 1, 'end': 1, 'buffer': 1, 'domain': 1, 'type': 1,
         'input_name': 1, 'filename': 1, 'has_logs': 1, 'status': 1, 'error': 1, 'logs': {'$slice': 1}})
    if item:
        g.task_doc = item
    return item


def enqueue_owned_task(result, worker='worker'):
    # Persist ownership before dispatch: status/authorization must work while queued.
    tasks = CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']]
    tasks.insert_one(dict(result, start=datetime.utcnow(), end=None, logs=[], status='queued'))
    try:
        return CELERY.send_task(json_settings[environ['project_env']][worker]['name'],
                                args=[result], task_id=result['task'],
                                queue=json_settings[environ['project_env']][worker]['queue'])
    except Exception:
        tasks.update_one({'task': result['task'], 'owner_id': result['owner_id']},
                         {'$set': {'dispatch_failed': True, 'status': 'failed',
                                   'end': datetime.utcnow(), 'error': 'Queue dispatch failed'}})
        raise


@APP.before_request
def limit_request_size():
    if request.path in EMAIL_UPLOAD_PATHS:
        return None
    # a chunked body has no length to check up front, and only the uploads need a large one
    chunked = 'chunked' in request.headers.get('Transfer-Encoding', '').lower()
    if chunked or (request.content_length or 0) > REQUEST_MAX_BYTES:
        return jsonify(error='Request too large'), 413


@APP.before_request
def enforce_task_ownership():
    task_id = (request.view_args or {}).get('task_id')
    if task_id is None:
        return None
    if not check_api_auth():
        return jsonify(error='Unauthorized'), 401
    if not owned_task(task_id):
        return jsonify(error='Task not found'), 404


class ApiKeysView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        owner_id = str(current_user.get_id())
        new_token = None
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'create':
                try:
                    new_token = create_api_key(api_key_collection(), owner_id,
                                               request.form.get('label', ''))
                except ValueError as exc:
                    flash(str(exc), 'error')
            elif action == 'revoke':
                try:
                    key_id = ObjectId(request.form.get('key_id', ''))
                except Exception:
                    return jsonify(error='Key not found'), 404
                if not revoke_api_key(api_key_collection(), owner_id, key_id):
                    return jsonify(error='Key not found'), 404
                flash('API key revoked.', 'success')
                return redirect(url_for('.index'))
            else:
                return jsonify(error='Invalid action'), 400
        keys = list(api_key_collection().find({'owner_id': owner_id}, {'digest': 0})
                    .sort('created_at', -1))
        response = APP.make_response(self.render('api_keys.html', keys=keys, new_token=new_token))
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response


@APP.route('/api/v1/analyze', methods=['POST'])
@CSRF.exempt
def api_analyze():
    if not check_api_auth():
        return jsonify(error="Unauthorized. Provide valid X-API-Key or Bearer token."), 401

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(error='Expected a JSON object'), 400
    try:
        timeouts = validate_timeouts(data)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    if not isinstance(data.get('url', data.get('buffer', '')), str):
        return jsonify(error='URL must be a string'), 400
    url, scheme_fallback = normalize_target(data.get("url") or data.get("buffer") or "")
    if not url:
        return jsonify(error="Missing required 'url' parameter."), 400

    try:
        url_validators.url(url)
    except Exception:
        return jsonify(error=f"Invalid URL format: '{url}'"), 400

    task_id = str(uuid4())
    result = {
        "task": task_id,
        "owner_id": request_owner_id(),
        "buffer": url,
        "scheme_fallback": scheme_fallback,
        "use_proxy": bool(data.get("use_tor", data.get("use_proxy", True))),
        "proxy": data.get("proxy", "socks5://proxy:9050"),
        "no_redirect": bool(data.get("no_redirect", False)),
        "take_screenshot": bool(data.get("take_screenshot", data.get("take_full_screenshot", True))),
        "take_full_screenshot": bool(data.get("take_full_screenshot", False)),
        "sniffer_on": bool(data.get("sniffer_on", False)),
        "interactive": bool(data.get("interactive", False)),
        "record_vnc": bool(data.get("record_vnc", False)),
        "block_cookies": bool(data.get("block_cookies", True)),
        **timeouts,
        "useragent": data.get("useragent", "Chrome"),
        "useragent_mapped": SWITCHES_MAPPED.get(data.get("useragent", "Chrome"), SWITCHES_MAPPED['Chrome'])
    }
    if result['use_proxy'] and not result['proxy']:
        result['proxy'] = 'socks5://proxy:9050'

    enqueue_owned_task(result)

    return jsonify({
        "status": "queued",
        "task_id": task_id,
        "target_url": url,
        "use_tor": result["use_proxy"],
        "use_proxy": result["use_proxy"],
        "created_at": datetime.utcnow().isoformat() + "Z"
    }), 201


@APP.route('/api/v1/analyze/email', methods=['POST'])
@CSRF.exempt
def api_analyze_email():
    '''
    multipart upload of one .eml or .msg file in the "file" field
    '''
    if not check_api_auth():
        return jsonify(error="Unauthorized. Provide valid X-API-Key or Bearer token."), 401
    task_id, error = queue_email(request.files.get('file'), request_owner_id())
    if error:
        return jsonify(error=error), 400
    return jsonify({
        "status": "queued",
        "task_id": task_id,
        "type": "email",
        "created_at": datetime.utcnow().isoformat() + "Z"
    }), 201


@APP.route('/api/v1/tasks/<task_id>', methods=['GET'])
@CSRF.exempt
def api_task_status(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    item = owned_task(task_id)
    if not item:
        return jsonify(error=f"Task '{task_id}' not found."), 404

    start = item.get("start")
    end = item.get("end")
    logs = item.get("logs") or []

    status = task_status(item)

    response = jsonify({
        "task_id": task_id,
        "target_url": item.get("buffer", ""),
        "status": status,
        "error": item.get('error'),
        "submitted_at": start.isoformat() + "Z" if start else None,
        "completed_at": end.isoformat() + "Z" if end else None,
        "duration": _format_duration(start, end)
    })
    # polled by the report page while a task runs: a cached answer would keep it waiting
    response.headers['Cache-Control'] = 'no-store'
    return response, 200


@APP.route('/api/v1/tasks/<task_id>/summary', methods=['GET'])
@CSRF.exempt
def api_task_summary(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    task_doc = owned_task(task_id)
    if not task_doc:
        return jsonify(error=f"Task '{task_id}' not found."), 404

    state = task_status(task_doc)
    if state in TERMINAL and state != 'completed':
        return jsonify(task_id=task_id, status=state,
                       error=task_doc.get('error') or 'Analysis did not complete successfully'), 422

    if not task_doc.get("end"):
        return jsonify({
            "task_id": task_id,
            "status": "running" if task_doc.get('has_logs') or task_doc.get("logs") else "queued",
            "message": "Analysis is still in progress. Check back shortly."
        }), 202

    if task_doc.get("type") == "email":
        analysis = load_email_analysis(task_id)
        if not analysis:
            return jsonify(error="Analysis output not found for this task."), 404
        return jsonify(email_summary(task_id, analysis)), 200

    import json
    ai_raw = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json; type=ai_summary"})
    if ai_raw:
        if isinstance(ai_raw, bytes):
            ai_raw = ai_raw.decode('utf-8', 'ignore')
        summary = json.loads(ai_raw)
        return summary_response(task_id, summary)

    raw_analyzer = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json"})
    if not raw_analyzer:
        return jsonify(error="Analysis output not found for this task."), 404

    try:
        if isinstance(raw_analyzer, bytes):
            raw_analyzer = raw_analyzer.decode('utf-8', 'ignore')
        parsed_analyzer = json.loads(raw_analyzer)
        heuristics = table_field(parsed_analyzer, 'extracted_table', 'ai_heuristics', {})
        cert = table_field(parsed_analyzer, 'extracted_table', 'Certificate', {})
        dns = table_field(parsed_analyzer, 'extracted_table', 'dns_records', [])

        fallback_summary = {
            "task_id": task_id,
            "status": "completed",
            "url_analysis": {
                "submitted_url": task_doc.get("buffer", ""),
                "final_url": heuristics.get("final_url", task_doc.get("buffer", "")),
                "initial_domain": task_doc.get("domain", ""),
                "final_domain": heuristics.get("final_domain", task_doc.get("domain", "")),
                "redirected": heuristics.get("redirected", False),
                "is_punycode_homograph": heuristics.get("is_punycode", False)
            },
            "page_content": {
                "page_title": heuristics.get("page_title", ""),
                "has_password_field": heuristics.get("has_password_field", False),
                "password_field_count": heuristics.get("password_field_count", 0),
                "has_credential_inputs": heuristics.get("has_credential_inputs", False),
                "has_credit_card_inputs": heuristics.get("has_credit_card_inputs", False),
                "form_action_targets": heuristics.get("form_actions", []),
                "detected_brands": heuristics.get("detected_brands", []),
                "brand_domain_mismatch": heuristics.get("brand_domain_mismatch", False)
            },
            "ssl_certificate": {
                "issuer": cert.get("Issuer", ""),
                "subject": cert.get("Subjects", ""),
                "valid_from": cert.get("Valid From", ""),
                "valid_until": cert.get("Valid Until", ""),
                "expired": cert.get("Expired", False)
            },
            "dns_records": dns,
            "threat_indicators": heuristics.get("threat_indicators", []),
            "screenshot_url": f"/api/v1/tasks/{task_id}/screenshot"
        }
        return summary_response(task_id, fallback_summary, parsed_analyzer)
    except Exception as ex:
        return jsonify(error=f"Error compiling summary: {str(ex)}"), 500


@APP.route('/api/v1/tasks/<task_id>/screenshot', methods=['GET'])
@CSRF.exempt
def api_task_screenshot(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    for kind in ('ai_image_jpeg', 'normal_image'):
        artifact = open_artifact(defaultdb['dbname'], task_id, kind)
        if artifact:
            return image_response(task_id, kind, artifact)
    image = task_image(task_id)
    if image:
        payload, mime = image
        return Response(payload, mimetype=mime)
    return jsonify(error=f"Screenshot not found for task '{task_id}'."), 404


def task_image(task_id, kind=None, analysis=None):
    kinds = (kind,) if kind else ('ai_image_jpeg', 'normal_image')
    for selected in kinds:
        image = get_artifact(defaultdb['dbname'], task_id, selected)
        if image:
            return image
    # Compatibility for existing inline reports; no filesystem path from JSON is opened.
    if analysis is None:
        import json
        raw = get_it_fs(defaultdb['dbname'], {'task': task_id, 'contentType': 'application/json'})
        if not raw:
            return None
        analysis = json.loads(raw)
    from binascii import unhexlify
    for selected in kinds:
        table = 'network_table' if selected == 'circular_layout' else 'screenshot_table'
        value = table_field(analysis, table, selected)
        if isinstance(value, str) and value:
            return unhexlify(value.encode()), ARTIFACT_NAMES[selected][1]
    return None


def summary_response(task_id, summary, analysis=None):
    if request.args.get('include_screenshot', 'true').lower() in ('false', '0', 'no'):
        summary.pop('screenshot_base64', None)
    else:
        current = get_artifact(defaultdb['dbname'], task_id, 'ai_image_jpeg') or get_artifact(defaultdb['dbname'], task_id, 'normal_image')
        if current or not summary.get('screenshot_base64'):
            from base64 import b64encode
            image = current or task_image(task_id, analysis=analysis)
            summary['screenshot_base64'] = (
                f'data:{image[1]};base64,{b64encode(image[0]).decode()}' if image else '')
    return jsonify(summary), 200


def image_response(task_id, kind, artifact=None):
    artifact = artifact or open_artifact(defaultdb['dbname'], task_id, kind)
    if artifact:
        file, metadata = artifact
        def chunks():
            while True:
                chunk = file.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        response = Response(chunks(), mimetype=metadata['content_type'])
        response.content_length = file.length
        response.set_etag(metadata['sha256'])
        response.headers['Cache-Control'] = 'private, no-cache'
        return response.make_conditional(request)
    image = task_image(task_id, kind)
    if image:
        return Response(image[0], mimetype=image[1])
    return jsonify(error='Image not found'), 404


@APP.route('/api/v1/tasks/<task_id>/images/<kind>', methods=['GET'])
@CSRF.exempt
def api_task_image(task_id, kind):
    if kind not in ARTIFACT_NAMES:
        return jsonify(error='Image not found'), 404
    return image_response(task_id, kind)


class CustomMenuLink(MenuLink):
    '''
    items will the header top left
    '''

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))


ADMIN = Admin(APP, "UrlProbe", index_view=CustomAdminIndexView(url='/'), base_template='base.html', template_mode='bootstrap3')
ADMIN.add_link(CustomMenuLink(name='Logout', category='', url="/logout", icon_type='glyph', icon_value='glyphicon glyphicon-log-out'))
ADMIN.add_view(CustomViewBufferForm(name="New Analysis", endpoint='url', menu_icon_type='glyph', menu_icon_value='glyphicon-plus'))
ADMIN.add_view(CustomViewEmailForm(name="New Email Analysis", endpoint='email', menu_icon_type='glyph', menu_icon_value='glyphicon-envelope'))
ADMIN.add_view(CustomQueueView(name="Task Queue", endpoint='queue', menu_icon_type='glyph', menu_icon_value='glyphicon-tasks', category='Monitor'))
ADMIN.add_view(CustomLogsView(name="Active Logs", endpoint='activelogs', menu_icon_type='glyph', menu_icon_value='glyphicon-flash', category='Monitor'))
ADMIN.add_view(ApiKeysView(name='API Keys', endpoint='apikeys', menu_icon_type='glyph', menu_icon_value='glyphicon-lock', category='Account'))
# Report / logs are reached from a task row in the queue, not from the sidebar.
ADMIN.add_view(CustomReportView(name='Report', endpoint='report'))
ADMIN.add_view(CustomTaskLogView(name='Task Log', endpoint='tasklog'))
ADMIN.add_view(CheckTask('Task', endpoint='task', menu_icon_type='glyph', menu_icon_value='glyphicon-user'))


@APP.before_request
def before_request():
    '''
    needed session fields
    '''
    session.permanent = True
    APP.permanent_session_lifetime = timedelta(minutes=60)
    session.modified = True


def handle_all_errors(error):
    code = 500
    if isinstance(error, HTTPException):
        code = error.code
    return jsonify(error='Error', code=code), code


for exc in default_exceptions:
    APP.register_error_handler(exc, handle_all_errors)
