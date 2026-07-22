'''
    __G__ = "(G)bd249ce4"
    backend -> worker
'''

from os import environ, getpid, path
from time import sleep
from datetime import datetime
from shutil import rmtree
from types import FunctionType
from docker import from_env
from binascii import hexlify
from json import dumps as jdumps
from jinja2 import Template
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded
from tldextract import extract as textract
from qbreport import make_report
from shared.settings import json_settings
from shared.logger import log_string, setup_task_logger, ignore_exception, cancel_task_logger

DOCKER_CLIENT = from_env()
CELERY = Celery(json_settings[environ["project_env"]]["celery_settings"]["name"],
                broker=json_settings[environ["project_env"]]["celery_settings"]["celery_broker_url"],
                backend=json_settings[environ["project_env"]]["celery_settings"]["celery_result_backend"])

CELERY.conf.update(
    CELERY_ACCEPT_CONTENT=["json"],
    CELERY_TASK_SERIALIZER="json",
    CELERY_RESULT_SERIALIZER="json",
    CELERY_TIMEZONE="America/Los_Angeles"
)


def clean_up():
    for container in DOCKER_CLIENT.containers.list():
        if "url-sandbox-box" in container.name:
            container.stop()


@CELERY.task(bind=True, name=json_settings[environ["project_env"]]["worker"]["name"], queue=json_settings[environ["project_env"]]["worker"]["queue"], soft_time_limit=json_settings[environ["project_env"]]["worker"]["task_time_limit"], time_limit=json_settings[environ["project_env"]]["worker"]["task_time_limit"] + 10, max_retries=0, default_retry_delay=5)
def analyze_url(self, parsed):
    setup_task_logger(parsed)
    log_string("Start analyzing", task=parsed['task'])
    temp_container = None
    try:
        parsed["domain"] = ""
        try:
            extracted = textract(parsed['buffer'])
            parsed["domain"] = "{}.{}".format(extracted.domain, extracted.suffix)
        except BaseException:
            pass
        log_string(parsed["domain"], task=parsed['task'])
        parsed['locations'] = json_settings[environ["project_env"]]["task_logs"]
        if parsed['use_proxy']:
            log_string("Proxy detected", task=parsed['task'])
            temp_container = DOCKER_CLIENT.containers.run("url-sandbox-box", command=[hexlify(jdumps(parsed).encode()).decode()], volumes={json_settings[environ["project_env"]]["output_folder"]: {'bind': json_settings[environ["project_env"]]["task_logs"]["box_output"], 'mode': 'rw'}}, detach=True, network="url-sandbox_frontend_box")
        else:
            log_string("No proxy, running privileged for custom tor config", task=parsed['task'])
            temp_container = DOCKER_CLIENT.containers.run("url-sandbox-box", command=[hexlify(jdumps(parsed).encode()).decode()], volumes={json_settings[environ["project_env"]]["output_folder"]: {'bind': json_settings[environ["project_env"]]["task_logs"]["box_output"], 'mode': 'rw'}}, detach=True, network="url-sandbox_frontend_box", privileged=True)
        temp_logs = ""
        if parsed.get('interactive'):
            log_string("Interactive mode requested. Waiting for analysis to complete...", task=parsed['task'])
            # The box binds the control socket early (so the frontend never hits
            # a connection-refused race), but the report must only be built once
            # the initial analysis output is fully saved. Wait for the box's
            # analysis-complete marker, not merely for the socket to appear.
            marker_path = path.join(json_settings[environ["project_env"]]["output_folder"], parsed['task'], "analysis.done")
            # Budget for the initial analysis to finish (marker appears). Give
            # headroom over analyzer_timeout for Tor bootstrap so a slow first
            # navigation does not trip the wait. This only bounds report timing;
            # the interactive session itself lives for interactive_timeout.
            marker_budget = int(parsed.get('analyzer_timeout', 60)) + 90
            ready = False
            for item in range(1, marker_budget):
                try:
                    temp_container.reload()
                    if temp_container.status == 'exited':
                        log_string("Container exited prematurely", task=parsed['task'])
                        break
                except Exception:
                    pass
                if path.exists(marker_path):
                    ready = True
                    break
                sleep(1)
            if ready:
                log_string("Interactive analysis complete, session ready!", task=parsed['task'])
            else:
                # Do NOT kill the container here: the interactive session must
                # stay alive for interactive_timeout, managed by the box. Build
                # the report from whatever analysis produced so far.
                log_string("Interactive analysis marker not seen in time; keeping session alive", task=parsed['task'])
        else:
            for item in range(1, parsed['analyzer_timeout']):
                temp_logs = temp_container.logs()
                if len(temp_logs) > 1:
                    if temp_logs.endswith(b"Done!!\n"):
                        break
                sleep(1)
            try:
                temp_container.stop()
            except Exception:
                pass

        if len(temp_logs) > 0:
            for item in temp_logs.split(b"\n"):
                with ignore_exception(Exception):
                    if len(item) > 0:
                        log_string(item.decode("utf-8"), task=parsed['task'])
        log_string("Parsing output", task=parsed['task'])
        parsed['locations']['box_output'] = json_settings[environ["project_env"]]["output_folder"]
    except Exception as e:
        log_string("Error -> {}".format(e), task=parsed['task'])
        if temp_container is not None:
            try:
                temp_container.stop()
                temp_container.remove()
            except Exception:
                pass
            temp_container = None
    # clean_up()
    try:
        if temp_container is not None and not parsed.get('interactive'):
            temp_container.stop()
            temp_container.remove()
    except Exception as e:
        log_string("Error -> {}".format(e), task=parsed['task'])
    parsed['locations']['box_output'] = json_settings[environ["project_env"]]["output_folder"]
    try:
        make_report(parsed)
    except Exception as e:
        log_string("Report error -> {}".format(e), task=parsed['task'])
    cancel_task_logger(parsed['task'])
