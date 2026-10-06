'''
    __G__ = "(G)bd249ce4"
    web interface
'''

from os import environ, path
from uuid import UUID, uuid4
from datetime import timedelta, datetime
from json import dumps
from bson.objectid import ObjectId
from flask import Flask, flash, g, jsonify, redirect, request, session, url_for, send_file
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
from shared.mongodbconn import CLIENT, get_it_fs
from shared.retention import cleanup_expired_analyses
from shared.apikeys import create_api_key, authenticate_api_key, revoke_api_key

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

APP = Flask(__name__)
APP.secret_key = json_settings[environ["project_env"]]["backend_key"]
APP.config['MONGODB_SETTINGS'] = json_settings[environ["project_env"]]["web_mongo"]
APP.config['SESSION_COOKIE_SAMESITE'] = "Lax"
ANALYZER_TIMEOUT = json_settings[environ["project_env"]]["analyzer_timeout"]
URL_TIMEOUT = json_settings[environ["project_env"]]["url_timeout"]
RD = Redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
CELERY = Celery(json_settings[environ["project_env"]]["celery_settings"]["name"],
                broker=json_settings[environ["project_env"]]["celery_settings"]["celery_broker_url"],
                backend=json_settings[environ["project_env"]]["celery_settings"]["celery_result_backend"])

CELERY.control.purge()
MONGO_DB = MongoEngine()
MONGO_DB.init_app(APP)
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
    login = fields.StringField(render_kw={"placeholder": "Username", "autocomplete": "off"})
    password = fields.PasswordField(render_kw={"placeholder": "Password", "autocomplete": "off"})

    def validate_login(self, field):
        '''
        log in
        '''
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
        if request.method == 'POST' and temp_form.validate():
            user = temp_form.get_user()
            if user is not None:
                login_user(user)

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
    submit = fields.SubmitField('Analyze', render_kw={"class": "btn"})
    submitandwait = fields.SubmitField('Analyze & Wait', render_kw={"class": "btn btn-secondary"})
    __order = ('buffer', 'choices', 'useragents', 'urltimeout', 'analyzertimeout', 'interactivetimeout', 'submit', 'submitandwait')

    def __iter__(self):
        temp_fields = list(super(BufferForm, self).__iter__())
        def get_field(fid): return next((f for f in temp_fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)


class CustomViewBufferForm(BaseView):
    '''
    upload buffer main form
    '''
    extra_js = ['/static/checktask.js']

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
        temp_form = BufferForm(request.form)
        if request.method == 'POST':
            if temp_form.buffer.data != "":
                good_url = False
                try:
                    url_validators.url(temp_form.buffer.data)
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
                    result["buffer"] = temp_form.buffer.data
                    result["proxy"] = 'socks5://proxy:9050' if result.get('use_proxy') else ''
                    result["task"] = task
                    result["owner_id"] = str(current_user.get_id())
                    result["analyzer_timeout"] = temp_form.analyzertimeout.data
                    result["url_timeout"] = temp_form.urltimeout.data
                    result["interactive_timeout"] = temp_form.interactivetimeout.data
                    result["useragent"] = temp_form.useragents.data
                    result["useragent_mapped"] = SWITCHES_MAPPED[temp_form.useragents.data]
                    enqueue_owned_task(result)
                    if request.form.get('submitandwait') == 'Analyze & Wait':
                        # stay on the page so the spinner can poll and show the
                        # finished report inline
                        flash(gettext(task), 'successandwaituuid')
                    else:
                        # plain submit — jump straight to the live task queue
                        flash(gettext('Analysis queued'), 'success')
                        return redirect('/queue/')
                else:
                    flash(gettext("Invalid URL"), 'error')
            else:
                flash(gettext("Something wrong"), 'error')
        return self.render("upload.html", header="New Analysis", form=temp_form, switches_details="")

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
            {"owner_id": owner_id}).sort([("start", -1)]).limit(limit)
        for item in cursor:
            start = item.get("start")
            end = item.get("end")
            logs = item.get("logs") or []
            if end:
                status = "completed"
            elif logs:
                status = "running"
            else:
                status = "queued"
            tasks.append({
                "task": item.get("task", ""),
                "target": item.get("buffer", "") or item.get("domain", "") or "—",
                "type": "File" if item.get("type") == "file" else "URL",
                "status": status,
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
        "completed": sum(1 for t in tasks if t["status"] == "completed"),
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
        body = ""
        with ignore_exception(Exception):
            item = get_it_fs(defaultdb["dbname"], {"task": task_id, 'contentType': 'text/html'})
            if item:
                found = BeautifulSoup(item, 'html.parser').find('body')
                body = found.decode_contents() if found else item.decode('utf-8', 'ignore')
        return self.render("report.html", task_id=task_id, report_body=body)

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
                logs = item.get("logs") or []
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
    docs = list(CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find(
        {"owner_id": owner_id}).sort([("start", -1)]).limit(100))
    lines = [line for doc in reversed(docs) for line in (doc.get('logs') or [])]
    return {"id": len(lines), "logs": "\n".join(lines)}


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
                return dumps(get_last_logs(json_content))
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
        report_doc = CLIENT[defaultdb["dbname"]][defaultdb["reportscoll"]].find_one({"task": task_id, "type": "text/html"})
        if report_doc:
            old_file_id = report_doc["file"]
            html_content = get_it_fs(defaultdb["dbname"], {"_id": old_file_id})
            if html_content:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Update normal viewport screenshot
                tbody = soup.find('tbody', class_='table-Screenshot')
                if tbody:
                    img = tbody.find('img', class_='fullsize')
                    if img:
                        img['src'] = "data:image/jpeg;base64, " + new_screenshot_base64
                        
                # Update full page screenshot if it is provided
                if new_full_screenshot_base64:
                    full_tbody = soup.find('tbody', class_='table-Full_Screenshot')
                    if full_tbody:
                        full_img = full_tbody.find('img', class_='fullsize')
                        if full_img:
                            full_img['src'] = "data:image/jpeg;base64, " + new_full_screenshot_base64
                        
                from gridfs import GridFS
                fs = GridFS(CLIENT[defaultdb["dbname"]])
                fs.delete(old_file_id)
                new_file_id = fs.put(str(soup).encode('utf-8'), filename=task_id, task=task_id, content_type="text/html")
                CLIENT[defaultdb["dbname"]][defaultdb["reportscoll"]].update_one({"_id": report_doc["_id"]}, {"$set": {"file": new_file_id}})
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
        
        response_data = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response_data += chunk
        client.close()
        
        res = json.loads(response_data.decode('utf-8'))
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
    
    import json
    output_dir = path.join(json_settings[environ["project_env"]]["output_folder"], task_id)
    session_path = path.join(output_dir, "vnc_session.json")
    socket_path = path.join(output_dir, "control.sock")
    video_path = path.join(output_dir, "session.mp4")

    saved = {}
    if path.exists(session_path):
        try:
            with open(session_path, 'r') as f:
                saved = json.load(f)
        except Exception:
            pass

    socket_alive = path.exists(socket_path)
    is_ended = (saved.get("status") == "ended")
    is_active = socket_alive and not is_ended
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
    return CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']].find_one(
        {'task': task_id, 'owner_id': owner_id})


def enqueue_owned_task(result):
    # Persist ownership before dispatch: status/authorization must work while queued.
    tasks = CLIENT[defaultdb['dbname']][defaultdb['taskdblogscoll']]
    tasks.insert_one(dict(result, start=datetime.utcnow(), end=None, logs=[]))
    try:
        return CELERY.send_task(json_settings[environ['project_env']]['worker']['name'],
                                args=[result],
                                queue=json_settings[environ['project_env']]['worker']['queue'])
    except Exception:
        tasks.update_one({'task': result['task'], 'owner_id': result['owner_id']},
                         {'$set': {'dispatch_failed': True}})
        raise


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
    url = (data.get("url") or data.get("buffer") or "").strip()
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
        "use_proxy": bool(data.get("use_tor", data.get("use_proxy", True))),
        "proxy": data.get("proxy", "socks5://proxy:9050"),
        "no_redirect": bool(data.get("no_redirect", False)),
        "take_screenshot": bool(data.get("take_screenshot", data.get("take_full_screenshot", True))),
        "take_full_screenshot": bool(data.get("take_full_screenshot", False)),
        "sniffer_on": bool(data.get("sniffer_on", False)),
        "interactive": bool(data.get("interactive", False)),
        "record_vnc": bool(data.get("record_vnc", False)),
        "block_cookies": bool(data.get("block_cookies", True)),
        "url_timeout": int(data.get("url_timeout", 10)),
        "analyzer_timeout": int(data.get("analyzer_timeout", 60)),
        "interactive_timeout": int(data.get("interactive_timeout", 300)),
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


@APP.route('/api/v1/tasks/<task_id>', methods=['GET'])
@CSRF.exempt
def api_task_status(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    item = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find_one({"task": task_id})
    if not item:
        return jsonify(error=f"Task '{task_id}' not found."), 404

    start = item.get("start")
    end = item.get("end")
    logs = item.get("logs") or []

    if end:
        status = "completed"
    elif logs:
        status = "running"
    else:
        status = "queued"

    return jsonify({
        "task_id": task_id,
        "target_url": item.get("buffer", ""),
        "status": status,
        "submitted_at": start.isoformat() + "Z" if start else None,
        "completed_at": end.isoformat() + "Z" if end else None,
        "duration": _format_duration(start, end)
    }), 200


@APP.route('/api/v1/tasks/<task_id>/summary', methods=['GET'])
@CSRF.exempt
def api_task_summary(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    task_doc = CLIENT[defaultdb["dbname"]][defaultdb["taskdblogscoll"]].find_one({"task": task_id})
    if not task_doc:
        return jsonify(error=f"Task '{task_id}' not found."), 404

    if not task_doc.get("end"):
        return jsonify({
            "task_id": task_id,
            "status": "running" if task_doc.get("logs") else "queued",
            "message": "Analysis is still in progress. Check back shortly."
        }), 202

    import json
    ai_raw = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json; type=ai_summary"})
    if ai_raw:
        if isinstance(ai_raw, bytes):
            ai_raw = ai_raw.decode('utf-8', 'ignore')
        return APP.response_class(ai_raw, mimetype='application/json'), 200

    raw_analyzer = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json"})
    if not raw_analyzer:
        return jsonify(error="Analysis output not found for this task."), 404

    try:
        if isinstance(raw_analyzer, bytes):
            raw_analyzer = raw_analyzer.decode('utf-8', 'ignore')
        parsed_analyzer = json.loads(raw_analyzer)
        extracted = parsed_analyzer.get("extracted_table", {})
        heuristics = extracted.get("ai_heuristics", {})
        cert = extracted.get("Certificate", {})
        dns = extracted.get("dns_records", [])

        normal_img = parsed_analyzer.get("screenshot_table", {}).get("normal_image", "")
        img_b64 = ""
        if normal_img:
            from binascii import unhexlify
            from base64 import b64encode
            img_b64 = f"data:image/jpeg;base64,{b64encode(unhexlify(normal_img.encode('utf-8'))).decode('utf-8')}"

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
            "screenshot_base64": img_b64,
            "screenshot_url": f"/api/v1/tasks/{task_id}/screenshot"
        }
        return jsonify(fallback_summary), 200
    except Exception as ex:
        return jsonify(error=f"Error compiling summary: {str(ex)}"), 500


@APP.route('/api/v1/tasks/<task_id>/screenshot', methods=['GET'])
@CSRF.exempt
def api_task_screenshot(task_id):
    if not check_api_auth():
        return jsonify(error="Unauthorized."), 401

    import json
    from binascii import unhexlify
    from flask import Response

    raw_analyzer = get_it_fs(defaultdb["dbname"], {"task": task_id, "contentType": "application/json"})
    if raw_analyzer:
        try:
            if isinstance(raw_analyzer, bytes):
                raw_analyzer = raw_analyzer.decode('utf-8', 'ignore')
            data = json.loads(raw_analyzer)
            screenshots = data.get("screenshot_table", {})
            ai_jpeg = screenshots.get("ai_image_jpeg")
            if ai_jpeg:
                return Response(unhexlify(ai_jpeg.encode('utf-8')), mimetype="image/jpeg")
            normal = screenshots.get("normal_image")
            if normal:
                return Response(unhexlify(normal.encode('utf-8')), mimetype="image/png")
        except Exception:
            pass

    return jsonify(error=f"Screenshot not found for task '{task_id}'."), 404


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
ADMIN.add_view(CustomQueueView(name="Task Queue", endpoint='queue', menu_icon_type='glyph', menu_icon_value='glyphicon-tasks', category='Monitor'))
ADMIN.add_view(CustomLogsView(name="Active Logs", endpoint='activelogs', menu_icon_type='glyph', menu_icon_value='glyphicon-flash', category='Monitor'))
ADMIN.add_view(ApiKeysView(name='API Keys', endpoint='apikeys', menu_icon_type='glyph', menu_icon_value='glyphicon-lock'))
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
