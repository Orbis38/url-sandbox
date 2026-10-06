'''
    __G__ = "(G)bd249ce4"
    box -> run
'''

from sys import argv
from binascii import unhexlify
from json import loads as jloads
from tinydb import TinyDB
from qbsandbox import chrome_driver
from qbsniffer import QSniffer
from socket import gethostbyname
import socket
import time
from os import path, makedirs

def wait_and_rotate_tor(proxy_host="proxy", control_port=9051, secret="urlsandbox_tor_secret", max_wait_sec=30):
    """Wait for Tor to reach 100% bootstrap and rotate the circuit via SIGNAL NEWNYM."""
    print(f"[SandBox Tor] Connecting to Tor control port {proxy_host}:{control_port}...", flush=True)
    start_time = time.time()
    s = None
    while time.time() - start_time < max_wait_sec:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((proxy_host, control_port))
            break
        except Exception:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
                s = None
            time.sleep(1)

    if not s:
        print("[SandBox Tor] Warning: could not connect to Tor control port", flush=True)
        return False

    try:
        s.sendall(f'AUTHENTICATE "{secret}"\r\n'.encode('utf-8'))
        resp = s.recv(1024).decode('utf-8')
        if '250' not in resp:
            print(f"[SandBox Tor] Auth failed: {resp.strip()}", flush=True)
            s.close()
            return False

        # Wait for bootstrap progress 100%
        bootstrapped = False
        while time.time() - start_time < max_wait_sec:
            s.sendall(b'GETINFO status/bootstrap-phase\r\n')
            resp = s.recv(1024).decode('utf-8')
            if 'PROGRESS=100' in resp:
                bootstrapped = True
                break
            time.sleep(1)

        if not bootstrapped:
            print("[SandBox Tor] Warning: Tor bootstrap timed out, proceeding anyway", flush=True)

        s.sendall(b'SIGNAL NEWNYM\r\nQUIT\r\n')
        s.recv(1024)
        s.close()
        print("[SandBox Tor] Tor circuit established & IP rotated (SIGNAL NEWNYM)", flush=True)
        return True
    except Exception as e:
        print(f"[SandBox Tor] Warning during Tor setup: {e}", flush=True)
        try:
            s.close()
        except Exception:
            pass
        return False


if len(argv) == 2:
    print("[SandBox] Parsing arguments")
    parsed = jloads(unhexlify(argv[1]).decode())
    task_dir = path.join(parsed['locations']['box_output'], parsed['task'])
    makedirs(task_dir, exist_ok=True)
    analyzer_logs = TinyDB(path.join(task_dir, parsed['task'] + parsed['locations']['analyzer_logs']))

    if parsed.get('use_proxy'):
        print("[SandBox] Using Tor proxy gateway")
        proxy_host = "proxy"
        try:
            proxy_ip = gethostbyname(proxy_host)
        except Exception:
            proxy_ip = proxy_host
        parsed['proxy'] = f'socks5://{proxy_ip}:9050'
        parsed['requests_proxy'] = f'socks5h://{proxy_ip}:9050'
        wait_and_rotate_tor(proxy_ip, 9051)
    else:
        print("[SandBox] Direct internet connection (no proxy)")
        parsed['proxy'] = ''
        parsed['requests_proxy'] = ''

    if parsed['sniffer_on']:
        print("[SandBox] Running Sniffer")
        sniffer_logs = TinyDB(path.join(task_dir, parsed['task'] + parsed['locations']['sniffer_logs']))
        x = QSniffer(parsed, '', 'eth0', sniffer_logs)
        x.run_sniffer(process=True)
    print("[SandBox] Testing with chrome webdriver")
    chrome_driver(parsed, analyzer_logs)
    print("[SandBox] Stopping Sniffer")
    if parsed['sniffer_on']:
        x.kill_sniffer(process=True)
    print("[SandBox] Done!!")
