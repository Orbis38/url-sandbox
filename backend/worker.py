'''
    __G__ = "(G)bd249ce4"
    backend -> worker
'''

from os import environ, path, makedirs
from uuid import UUID
from time import sleep
from docker import from_env
from binascii import hexlify
from json import dumps as jdumps
from celery import Celery
from tldextract import extract as textract
from qbreport import make_report
from shared.settings import json_settings
from shared.logger import log_string, setup_task_logger, ignore_exception, cancel_task_logger
from shared.retention import cleanup_expired_analyses
from shared.mongodbconn import ensure_indexes
from shared.security import validate_timeouts

DOCKER_CLIENT = from_env()
ensure_indexes()
CELERY = Celery(json_settings[environ["project_env"]]["celery_settings"]["name"],
                broker=json_settings[environ["project_env"]]["celery_settings"]["celery_broker_url"],
                backend=json_settings[environ["project_env"]]["celery_settings"]["celery_result_backend"])

CELERY.conf.update(
    task_acks_late=False,
    task_reject_on_worker_lost=False,
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    timezone="America/Los_Angeles"
)

# Run retention cleanup on startup to ensure 60-day policy (users kept indefinitely)
try:
    cleanup_expired_analyses(days=json_settings[environ["project_env"]].get("retention_days", 60), project_env=environ["project_env"])
except Exception as _ce:
    print(f"Worker startup retention check: {_ce}", flush=True)


def find_free_port(start=6080, end=6100):
    allocated = set()
    try:
        for c in DOCKER_CLIENT.containers.list():
            ports_dict = c.ports or {}
            for port_list in ports_dict.values():
                if port_list:
                    for binding in port_list:
                        hp = binding.get('HostPort')
                        if hp:
                            allocated.add(int(hp))
    except Exception:
        pass

    try:
        import redis
        rd = redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
        active_in_redis = rd.smembers("active_vnc_ports") or set()
        for p in list(active_in_redis):
            try:
                port_num = int(p)
                if port_num not in allocated:
                    rd.srem("active_vnc_ports", p)
                else:
                    allocated.add(port_num)
            except Exception:
                pass
    except Exception:
        pass

    for port in range(start, end):
        if port not in allocated:
            try:
                import redis
                rd = redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
                rd.sadd("active_vnc_ports", port)
            except Exception:
                pass
            return port
    return start


def release_vnc_port(port):
    if not port:
        return
    try:
        import redis
        rd = redis.from_url(json_settings[environ["project_env"]]["redis_settings"])
        rd.srem("active_vnc_ports", port)
    except Exception:
        pass


@CELERY.task(bind=True, name=json_settings[environ["project_env"]]["worker"]["name"], queue=json_settings[environ["project_env"]]["worker"]["queue"], soft_time_limit=json_settings[environ["project_env"]]["worker"]["task_time_limit"], time_limit=json_settings[environ["project_env"]]["worker"]["task_time_limit"] + 10, max_retries=0, default_retry_delay=5)
def analyze_url(self, parsed):
    # Broker input must not select arbitrary filesystem paths/container names.
    if str(UUID(parsed['task'])) != parsed['task'] or not parsed.get('owner_id'):
        raise ValueError('A canonical task UUID and owner are required')
    parsed.update(validate_timeouts(parsed))
    if not setup_task_logger(parsed):
        return  # A started/terminal task must never be automatically replayed.
    log_string("Start analyzing", task=parsed['task'])
    temp_container = None
    outcome, failure = 'completed', None
    try:
        parsed["domain"] = ""
        try:
            extracted = textract(parsed['buffer'])
            parsed["domain"] = "{}.{}".format(extracted.domain, extracted.suffix)
        except BaseException:
            pass
        log_string(parsed["domain"], task=parsed['task'])
        parsed['locations'] = dict(json_settings[environ["project_env"]]["task_logs"])
        ports = None
        if parsed.get('interactive'):
            vnc_port = find_free_port(6080, 6100)
            parsed['vnc_port'] = vnc_port
            ports = {'6080/tcp': vnc_port}
            log_string("Interactive mode: assigned host VNC port {}".format(vnc_port), task=parsed['task'])
        if parsed.get('use_proxy'):
            log_string("Routing via Tor proxy gateway", task=parsed['task'])
        else:
            log_string("Direct network connection (no proxy)", task=parsed['task'])

        output_vol = json_settings[environ["project_env"]].get("docker_volume_output") or json_settings[environ["project_env"]]["output_folder"]
        task_output = path.join(json_settings[environ['project_env']]['output_folder'], parsed['task'])
        makedirs(task_output, exist_ok=True)
        if json_settings[environ['project_env']].get('docker_volume_output'):
            host_output = DOCKER_CLIENT.volumes.get(output_vol).attrs['Mountpoint']
        else:
            host_output = output_vol
        # Bind only this task's directory, never the entire shared artifact volume.
        host_task_output = path.join(host_output, parsed['task'])
        box_task_output = path.join(parsed['locations']['box_output'], parsed['task'])
        container_name = f"url-sandbox_box_{parsed['task']}"
        try:
            existing_c = DOCKER_CLIENT.containers.get(container_name)
            existing_c.remove(force=True)
        except Exception:
            pass

        temp_container = DOCKER_CLIENT.containers.run(
            "url-sandbox-box",
            name=container_name,
            command=[hexlify(jdumps(parsed).encode()).decode()],
            volumes={host_task_output: {'bind': box_task_output, 'mode': 'rw'}},
            detach=True,
            network="url-sandbox_frontend_box",
            ports=ports,
            labels={'url-sandbox.managed': 'true', 'url-sandbox.task': parsed['task']}
        )
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
                outcome, failure = 'timed_out', 'Initial interactive analysis did not complete in time'
                # Do NOT kill the container here: the interactive session must
                # stay alive for interactive_timeout, managed by the box. Build
                # the report from whatever analysis produced so far.
                log_string("Interactive analysis marker not seen in time; keeping session alive", task=parsed['task'])
        else:
            finished = False
            for item in range(1, parsed['analyzer_timeout']):
                try:
                    temp_container.reload()
                    if temp_container.status == 'exited':
                        temp_logs = temp_container.logs()
                        finished = b'Done!!' in temp_logs
                        break
                except Exception:
                    pass
                temp_logs = temp_container.logs()
                if len(temp_logs) > 1 and b"Done!!" in temp_logs:
                    finished = True
                    break
                sleep(1)
            if not finished:
                outcome, failure = 'timed_out', 'Analysis stopped before completion'
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
        outcome, failure = 'failed', str(e)
        log_string("Error -> {}".format(e), task=parsed['task'])
        if temp_container is not None:
            try:
                temp_container.stop()
                temp_container.remove()
            except Exception:
                pass
            temp_container = None
            release_vnc_port(parsed.get('vnc_port'))
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
        outcome, failure = 'failed', 'Report generation failed'
    cancel_task_logger(parsed['task'], outcome, failure)
