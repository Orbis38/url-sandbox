'''
    __G__ = "(G)bd249ce4"
    box -> sandbox
'''

from time import sleep
from json import loads, dumps
from warnings import filterwarnings
from subprocess import Popen, DEVNULL, PIPE
import os
import signal
from urllib.parse import urlparse
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from tinydb import TinyDB
from binascii import hexlify
from bs4 import BeautifulSoup
from requests import get as rget, head as rhead
from requests.packages.urllib3.connection import VerifiedHTTPSConnection
from networkx import Graph, circular_layout
from io import BytesIO
from dns.resolver import resolve
import matplotlib.pyplot as plt

filterwarnings("ignore", category=DeprecationWarning)
DISPLAY = Display(visible=0, size=(1440, 900))
X509 = None


def get_dns(parsed, extracted_table):
    try:
        temp_list = []
        for records in ['A', 'AAAA', 'CNAME', 'MX', 'SRV', 'TXT', 'SOA', 'NS']:
            try:
                answer = resolve(parsed['domain'], records, raise_on_no_answer=False)
                if answer.rrset is not None:
                    temp_list.append({records: answer.rrset.to_text()})
            except BaseException:
                pass
        if len(temp_list) > 0:
            extracted_table.insert({'dns_records': temp_list})
    except Exception as e:
        print(e)
        print("[SandBox] get_dns failed")

def make_network(analyzer_table, network_graph):
    try:
        list_domain_counters = []
        dict_domain_counters = {}
        domain_counter = 0
        for item in analyzer_table.all():
            try:
                if 'headers' in item:
                    if 'Host' in item['headers']:
                        if item['headers']['Host'] not in list_domain_counters:
                            list_domain_counters.append(item['headers']['Host'])
                            dict_domain_counters.update({domain_counter: item['headers']['Host']})
                            domain_counter += 1
                    if ':authority' in item['headers']:
                        if item['headers'][':authority'] not in list_domain_counters:
                            list_domain_counters.append(item['headers'][':authority'])
                            dict_domain_counters.update({domain_counter: item['headers'][':authority']})
                            domain_counter += 1
            except BaseException:
                pass

        G = Graph()
        if len(list_domain_counters) > 0:
            for key, value in dict_domain_counters.items():
                G.add_node(key, text=value)
                if key != 0:
                    G.add_edge(0, key)

            pos = circular_layout(G)
            fig = plt.figure(figsize=(10, 5), facecolor='w')
            ax = fig.add_subplot(111)
            plt.xlim(-1.5, 1.5)
            plt.ylim(-1.5, 1.5)

            for edges in G.edges:
                ax.annotate("",
                            xy=pos[edges[0]], xycoords='data',
                            xytext=pos[edges[1]], textcoords='data',
                            arrowprops=dict(arrowstyle='-', color="r", shrinkA=7, shrinkB=7, patchA=None, patchB=None, connectionstyle="arc3,rad=-0.1",),)
            for node in G:
                x, y = pos[node]
                ax.text(x, y, G.nodes[node]['text'], fontsize=10, bbox=dict(boxstyle='round', facecolor='#D3D3D3', alpha=1, linewidth=0), zorder=99)
            ax.axis('off')
            buf = BytesIO()
            plt.savefig(buf, bbox_inches='tight', dpi=100)
            buf.seek(0)
            network_graph.insert({'circular_layout': hexlify(buf.read()).decode('utf-8')})
            print("[SandBox] saved network graph")
    except BaseException:
        print("[SandBox] make_network failed")


def get_headers(parsed, extracted_table):
    try:
        response = None
        headers = {'User-Agent': parsed['useragent_mapped']}
        proxy_url = parsed.get('requests_proxy') or parsed.get('proxy')
        if parsed.get('use_proxy') and proxy_url:
            proxies = {'http': proxy_url,
                       'https': proxy_url}
            response = rhead(parsed['buffer'], proxies=proxies, headers=headers, timeout=10)
            response.headers['response_status'] = response.status_code
        else:
            response = rhead(parsed['buffer'], headers=headers, timeout=10)
            response.headers['response_status'] = response.status_code
        if len(response.headers) > 0:
            extracted_table.insert({'Request_Headers': dict(response.request.headers)})
            extracted_table.insert({'Response_Headers': dict(response.headers)})
            print("[SandBox] extracted request and response headers")
    except Exception as e:
        print("[SandBox] get_headers failed")


def get_cert(parsed, extracted_table):
    try:
        mapped = {b'CN': b'Common Name', b'OU': b'Organizational Unit', b'O': b'Organization', b'L': b'Locality', b'ST': b'State Or Province Name', b'C': b'Country Name'}
        import OpenSSL.crypto
        from urllib3.connection import HTTPSConnection
        try:
            from urllib3.contrib.socks import SOCKSHTTPSConnection
        except Exception:
            SOCKSHTTPSConnection = None

        global X509
        X509 = None

        def extract_x509(sock):
            global X509
            try:
                if hasattr(sock, 'connection'):
                    X509 = sock.connection.get_peer_certificate()
                elif hasattr(sock, 'getpeercert'):
                    der = sock.getpeercert(binary_form=True)
                    if der:
                        X509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
            except Exception:
                pass

        orig_https = HTTPSConnection.connect
        def hooked_https(self):
            orig_https(self)
            extract_x509(self.sock)
        HTTPSConnection.connect = hooked_https

        if SOCKSHTTPSConnection:
            orig_socks = SOCKSHTTPSConnection.connect
            def hooked_socks(self):
                orig_socks(self)
                extract_x509(self.sock)
            SOCKSHTTPSConnection.connect = hooked_socks

        headers = {'User-Agent': parsed['useragent_mapped']}
        proxy_url = parsed.get('requests_proxy') or parsed.get('proxy')
        if parsed.get('use_proxy') and proxy_url:
            proxies = {'http': proxy_url,
                       'https': proxy_url}
            rget(parsed['buffer'], proxies=proxies, headers=headers, timeout=10)
        else:
            rget(parsed['buffer'], headers=headers, timeout=10)

        if not X509:
            print("[SandBox] get_cert: no certificate captured")
            return
        List_ = {}
        List_['Subjects'] = []
        for subject in X509.get_subject().get_components():
            try:
                List_['Subjects'].append({mapped[subject[0]].decode('utf-8'): subject[1].decode('utf-8')})
            except BaseException:
                pass
        List_['Subject Hash'] = X509.get_subject().hash()
        List_['Issuer'] = []
        for issuer in X509.get_issuer().get_components():
            try:
                List_['Issuer'].append({mapped[issuer[0]].decode('utf-8'): issuer[1].decode('utf-8')})
            except BaseException:
                pass
        List_['Issuer Hash'] = X509.get_issuer().hash()
        List_['Extensions'] = []
        for extension in range(X509.get_extension_count()):
            List_['Extensions'].append({X509.get_extension(extension).get_short_name().decode('utf-8'): X509.get_extension(extension).__str__()})
        List_['Expired'] = X509.has_expired()
        List_['Valid From'] = X509.get_notBefore().decode('utf-8')
        List_['Valid Until'] = X509.get_notAfter().decode('utf-8')
        List_['Signature Algorithm'] = X509.get_signature_algorithm().decode('utf-8')
        List_['Serial Number'] = X509.get_serial_number()
        List_['MD5 Digest'] = X509.digest('md5').decode('utf-8')
        List_['SHA1 Digest'] = X509.digest('sha1').decode('utf-8')
        List_['SHA224 Digest'] = X509.digest('sha224').decode('utf-8')
        List_['SHA256 Digest'] = X509.digest('sha256').decode('utf-8')
        List_['SHA384 Digest'] = X509.digest('sha384').decode('utf-8')
        List_['SHA512 Digest'] = X509.digest('sha512').decode('utf-8')
        extracted_table.insert({'Certificate': List_})
        print("[SandBox] extracted certificate")
    except BaseException:
        print("[SandBox] get_cert failed")


def get_all_links(html, extracted_table):
    try:
        temp_table = []
        parsed_table = []
        for a_tag in BeautifulSoup(html, 'html.parser').findAll("a"):
            try:
                temp_link = "{} > {}".format(a_tag['href'], a_tag.text)
                if temp_link not in temp_table:
                    temp_table.append(temp_link)
                    parsed_table.append({"link": a_tag['href'], "text": a_tag.text})
            except BaseException:
                pass
        if len(parsed_table) > 0:
            extracted_table.insert({"extracted_links": parsed_table})
            print("[SandBox] extracted links")
    except BaseException:
        print("[SandBox] get_all_links failed")


def get_all_scripts(html, extracted_table):
    try:
        temp_table = []
        parsed_table = []
        for script in BeautifulSoup(html, 'html.parser').findAll("script"):
            temp_link = "{}".format(script)
            if temp_link not in temp_table:
                temp_table.append(temp_link)
                try:
                    parsed_table.append({"script": str(script)})
                except BaseException:
                    pass
        if len(parsed_table) > 0:
            extracted_table.insert({"extracted_scripts": parsed_table})
            print("[SandBox] extracted scripts")
    except BaseException:
        print("[SandBox] get_all_links failed")


def make_ai_screenshot_jpeg(png_bytes, max_size=(1280, 800), quality=82):
    '''
    Create a compressed, downscaled JPEG specifically optimized for local AI vision models (Gemma)
    '''
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(png_bytes)).convert('RGB')
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=quality, optimize=True)
        return buf.getvalue()
    except Exception as e:
        print(f"[SandBox] make_ai_screenshot_jpeg failed: {e}", flush=True)
        return None


def take_normal_screen_shot(driver, screenshot_table):
    '''
    get normal screenshot and generate lightweight JPEG for AI vision (Gemma)
    '''
    try:
        screenshot = driver.get_screenshot_as_png()
        entry = {'normal_image': hexlify(screenshot).decode('utf-8')}
        ai_jpeg = make_ai_screenshot_jpeg(screenshot)
        if ai_jpeg:
            entry['ai_image_jpeg'] = hexlify(ai_jpeg).decode('utf-8')
        screenshot_table.insert(entry)
        print("[SandBox] Screenshot saved (including AI vision JPEG)")
    except BaseException:
        print("[SandBox] take_normal_screen_shot failed")


def extract_phishing_heuristics(driver, parsed, extracted_table):
    '''
    Extract high-signal security heuristics for AI triage (Gemma) and playbooks
    '''
    try:
        current_url = driver.current_url or parsed.get('buffer', '')
        title = driver.title or ''
        
        init_parsed = urlparse(parsed.get('buffer', ''))
        curr_parsed = urlparse(current_url)
        initial_domain = init_parsed.netloc.split(':')[0]
        final_domain = curr_parsed.netloc.split(':')[0]
        redirected = (initial_domain.lower() != final_domain.lower()) or (parsed.get('buffer', '') != current_url)
        is_punycode = 'xn--' in final_domain.lower()

        dom_probe_js = """
        try {
            var forms = [];
            var formEls = document.querySelectorAll('form');
            for (var i = 0; i < formEls.length; i++) {
                var f = formEls[i];
                var action = f.getAttribute('action') || '';
                var method = (f.getAttribute('method') || 'GET').toUpperCase();
                forms.push({ action: action, method: method });
            }
            var pwds = document.querySelectorAll('input[type="password"]');
            var emails = document.querySelectorAll('input[type="email"], input[name*="email" i], input[name*="user" i], input[name*="login" i], input[name*="usr" i]');
            var ccs = document.querySelectorAll('input[name*="card" i], input[name*="cvv" i], input[name*="cvc" i], input[name*="exp" i]');
            var bodyText = (document.body ? (document.body.innerText || document.body.textContent || '') : '').slice(0, 3000);
            return {
                forms: forms,
                has_password: pwds.length > 0,
                password_count: pwds.length,
                has_credentials: (pwds.length > 0 || emails.length > 0),
                has_credit_card: ccs.length > 0,
                body_sample: bodyText
            };
        } catch(e) {
            return { forms: [], has_password: false, password_count: 0, has_credentials: false, has_credit_card: false, body_sample: '' };
        }
        """
        dom_data = driver.execute_script(dom_probe_js) or {}

        COMMON_PHISHING_BRANDS = {
            'Microsoft': ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com', 'sharepoint.com', 'azure.com', 'msn.com', 'windows.com', 'outlook.com'],
            'Google': ['google.com', 'google.it', 'gmail.com', 'youtube.com'],
            'Apple': ['apple.com', 'icloud.com'],
            'PayPal': ['paypal.com', 'paypal.me'],
            'Amazon': ['amazon.com', 'amazon.it'],
            'Netflix': ['netflix.com'],
            'DHL': ['dhl.com', 'dhl.it', 'dhl-express.com'],
            'FedEx': ['fedex.com'],
            'UPS': ['ups.com'],
            'Poste Italiane': ['poste.it', 'postepay.it'],
            'Intesa Sanpaolo': ['intesasanpaolo.com'],
            'UniCredit': ['unicredit.it'],
            'DocuSign': ['docusign.com', 'docusign.net'],
            'Meta': ['facebook.com', 'meta.com', 'instagram.com'],
            'Adobe': ['adobe.com']
        }

        detected_brands = []
        brand_mismatch = False
        text_to_check = (title + " " + dom_data.get('body_sample', '')).lower()
        
        for brand_name, valid_domains in COMMON_PHISHING_BRANDS.items():
            if brand_name.lower() in text_to_check:
                detected_brands.append(brand_name)
                is_legit = any(final_domain.lower() == vd or final_domain.lower().endswith('.' + vd) for vd in valid_domains)
                if not is_legit:
                    brand_mismatch = True

        indicators = []
        if dom_data.get('has_password'):
            indicators.append('credential_input_present')
        if dom_data.get('has_credit_card'):
            indicators.append('credit_card_input_present')
        if brand_mismatch:
            indicators.append('brand_domain_mismatch')
        if is_punycode:
            indicators.append('punycode_homograph_domain')
        if redirected:
            indicators.append('cross_domain_redirect')
        
        form_actions = [f.get('action') for f in dom_data.get('forms', []) if f.get('action')]
        for fa in form_actions:
            if fa.startswith('http://') or fa.startswith('https://'):
                act_domain = urlparse(fa).netloc.split(':')[0]
                if act_domain.lower() != final_domain.lower() and act_domain:
                    indicators.append('cross_domain_form_submission')
                    break

        if 'windows + r' in text_to_check or 'powershell' in text_to_check:
            indicators.append('clickfix_powershell_lure')

        heuristics = {
            'submitted_url': parsed.get('buffer', ''),
            'final_url': current_url,
            'initial_domain': initial_domain,
            'final_domain': final_domain,
            'redirected': redirected,
            'is_punycode': is_punycode,
            'page_title': title,
            'has_password_field': dom_data.get('has_password', False),
            'password_field_count': dom_data.get('password_count', 0),
            'has_credential_inputs': dom_data.get('has_credentials', False),
            'has_credit_card_inputs': dom_data.get('has_credit_card', False),
            'form_actions': form_actions,
            'detected_brands': detected_brands,
            'brand_domain_mismatch': brand_mismatch,
            'threat_indicators': indicators
        }
        extracted_table.insert({'ai_heuristics': heuristics})
        print(f"[SandBox] Extracted AI heuristics (indicators: {indicators})", flush=True)
        return heuristics
    except Exception as e:
        print(f"[SandBox] extract_phishing_heuristics failed: {e}", flush=True)
        return {}


def take_full_screen_shot(driver, screenshot_table):
    '''
    capture full screenshot
    '''
    try:
        element = driver.find_element(By.TAG_NAME, 'html')
        screenshot = element.get_screenshot_as_png()
        screenshot_table.insert({'full_image': hexlify(screenshot).decode('utf-8')})
        print("[SandBox] Screenshot saved")
    except BaseException:
        print("[SandBox] take_full_screen_shot failed")


def find_key(key, data):
    '''
    recursive key checking
    '''
    for k, v in data.items():
        if k == key:
            return v
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    result = find_key(key, i)
                    if result is not None:
                        return result
        elif isinstance(v, dict):
            result = find_key(key, v)
            if result is not None:
                return result


def parse_ouput(logs, table):
    try:
        performance_events = [loads(e['message'])['message'] for e in logs]
        network_events = [e for e in performance_events if 'network.' in e['method'].lower()]
        for _ in network_events:
            rec = find_key("headers", _)
            if rec:
                if "Network.responseReceived" in _["method"]:
                    table.insert({"type": "Received", "headers": rec})
                elif "Network.requestWillBeSent" in _["method"]:
                    table.insert({"type": "Sent", "headers": rec})
        print("[SandBox] parsed output")
    except BaseException:
        print("[SandBox] parse_ouput failed")


COOKIE_DISMISS_JS = r"""
try {
  // Common accept/reject wording across CMPs and languages.
  var WORDS = ['accept all','accept','agree','i agree','allow all','allow',
               'got it','ok','understand','continue','reject all','reject',
               'decline','deny','refuse','only necessary','necessary only',
               'accetta','accetto','rifiuta','consenti','ho capito',
               'akzeptieren','ablehnen','zustimmen','accepter','refuser',
               'aceptar','rechazar'];
  function txt(el){ return (el.innerText || el.textContent || '').trim().toLowerCase(); }
  var clicked = false;
  var candidates = document.querySelectorAll(
    'button, a, [role=button], input[type=button], input[type=submit]');
  for (var i = 0; i < candidates.length && !clicked; i++) {
    var el = candidates[i];
    if (el.offsetParent === null) continue;         // not visible
    var t = txt(el);
    if (!t || t.length > 40) continue;
    for (var j = 0; j < WORDS.length; j++) {
      if (t === WORDS[j] || t.indexOf(WORDS[j]) === 0) { try { el.click(); clicked = true; } catch(e){} break; }
    }
  }
  // Hide known consent containers and any leftover fixed/sticky overlays.
  var SEL = ['#onetrust-consent-sdk','#onetrust-banner-sdk','.ot-sdk-container',
             '#CybotCookiebotDialog','#cookiebanner','.cookie-banner','.cookie-consent',
             '[id*="cookie"]','[class*="cookie"]','[id*="consent"]','[class*="consent"]',
             '.qc-cmp2-container','#usercentrics-root','[aria-label*="cookie" i]',
             '[aria-label*="consent" i]'];
  SEL.forEach(function(s){
    document.querySelectorAll(s).forEach(function(el){
      var r = el.getBoundingClientRect();
      var pos = getComputedStyle(el).position;
      if ((pos === 'fixed' || pos === 'sticky' || pos === 'absolute') && r.height > 0) {
        el.style.setProperty('display','none','important');
      }
    });
  });
  // Restore scrolling that banners often lock.
  document.documentElement.style.setProperty('overflow','auto','important');
  document.body.style.setProperty('overflow','auto','important');
} catch (e) {}
"""


def dismiss_cookie_banners(driver, settle=0.6):
    '''
    click common cookie-consent accept/reject buttons and hide leftover
    banners so they do not appear in the captured screenshot.

    The hide step is synchronous, so a single pass already clears banners.
    The optional second pass (after `settle`) only catches banners that
    animate in after the accept click. Interactive mode passes settle=0 so
    this never delays the control-socket startup the worker is waiting on.
    '''
    try:
        driver.execute_script(COOKIE_DISMISS_JS)
        if settle:
            sleep(settle)
            driver.execute_script(COOKIE_DISMISS_JS)
        print("[SandBox] Cookie banners dismissed")
    except BaseException:
        print("[SandBox] dismiss_cookie_banners failed")


def chrome_driver(parsed, analyzer_db):
    '''
    init webdriver and submit parsed options
    '''
    DISPLAY.start()
    vnc_processes = []
    ffmpeg_proc = None
    video_file = os.path.join(parsed['locations']['box_output'], parsed['task'], "session.mp4")

    if parsed.get('interactive'):
        disp = getattr(DISPLAY, 'new_display_var', None) or os.environ.get("DISPLAY", ":0")
        os.environ["DISPLAY"] = disp
        print(f"[SandBox] Starting X11 desktop environment on {disp} for live 30 FPS interactive session", flush=True)
        try:
            ob_proc = Popen(["openbox"], stdout=DEVNULL, stderr=DEVNULL)
            vnc_processes.append(ob_proc)
        except Exception as e:
            print(f"[SandBox] Warning starting openbox: {e}", flush=True)
        try:
            vnc_proc = Popen([
                "x11vnc",
                "-display", disp,
                "-rfbport", "5900",
                "-shared",
                "-forever",
                "-nopw",
                "-wait", "33",
                "-defer", "20",
                "-repeat",
                "-cursor", "arrow"
            ], stdout=DEVNULL, stderr=DEVNULL)
            vnc_processes.append(vnc_proc)
        except Exception as e:
            print(f"[SandBox] Warning starting x11vnc: {e}", flush=True)
        try:
            ws_proc = Popen([
                "websockify",
                "--web", "/usr/share/novnc",
                "6080",
                "localhost:5900"
            ], stdout=DEVNULL, stderr=DEVNULL)
            vnc_processes.append(ws_proc)
        except Exception as e:
            print(f"[SandBox] Warning starting websockify: {e}", flush=True)

        if parsed.get('record_vnc'):
            try:
                task_dir = os.path.join(parsed['locations']['box_output'], parsed['task'])
                os.makedirs(task_dir, exist_ok=True)
                print(f"[SandBox] Starting ffmpeg recording of {disp} to {video_file}", flush=True)
                ffmpeg_proc = Popen([
                    "ffmpeg", "-y",
                    "-video_size", "1440x900",
                    "-framerate", "15",
                    "-f", "x11grab",
                    "-i", f"{disp}.0",
                    "-c:v", "libx264",
                    "-preset", "ultrafast",
                    "-crf", "28",
                    "-pix_fmt", "yuv420p",
                    "-movflags", "+frag_keyframe+empty_moov+default_base_moof",
                    video_file
                ], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
            except Exception as e:
                print(f"[SandBox] Warning starting ffmpeg: {e}", flush=True)

        # Write initial session metadata for the web interface
        try:
            task_dir = os.path.join(parsed['locations']['box_output'], parsed['task'])
            os.makedirs(task_dir, exist_ok=True)
            session_meta_path = os.path.join(task_dir, "vnc_session.json")
            with open(session_meta_path, "w") as smf:
                smf.write(dumps({
                    "task": parsed['task'],
                    "vnc_port": parsed.get('vnc_port'),
                    "status": "active",
                    "record_vnc": bool(parsed.get('record_vnc')),
                    "has_video": False
                }))
        except Exception as e:
            print(f"[SandBox] Warning writing vnc_session.json: {e}", flush=True)

    analyzer_table = analyzer_db.table('analyzer_table')
    extracted_table = analyzer_db.table('extracted_table')
    screenshot_table = analyzer_db.table('screenshot_table')
    network_table = analyzer_db.table('network_table')
    get_dns(parsed, extracted_table)
    get_headers(parsed, extracted_table)
    chrome_options = ChromeOptions()
    # Return control at DOMContentLoaded rather than waiting for every image,
    # font and tracker to finish — big speedup on heavy pages, screenshot still
    # captures the rendered document.
    chrome_options.page_load_strategy = 'eager'
    if parsed.get('interactive'):
        chrome_options.add_argument('--window-size=1440,900')
        chrome_options.add_argument('--window-position=0,0')
        chrome_options.add_argument('--start-maximized')
        chrome_options.add_argument('--disable-infobars')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--no-first-run')
        chrome_options.add_argument('--no-default-browser-check')
    else:
        chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--user-agent={}'.format(parsed['useragent_mapped']))
    if parsed.get('use_proxy') and parsed.get('proxy'):
        chrome_options.add_argument('--proxy-server=%s' % parsed['proxy'])
    # Always deny permission prompts (notifications, geolocation, camera/mic) so
    # they never steal focus or appear in the captured screenshot. 2 == block.
    chrome_options.add_argument('--deny-permission-prompts')
    # Anti-bot detection / stealth: hide navigator.webdriver
    chrome_options.add_argument('--disable-blink-features=AutomationControlled')
    chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    chrome_options.add_experimental_option('prefs', {
        'profile.default_content_setting_values.notifications': 2,
        'profile.default_content_setting_values.geolocation': 2,
        'profile.default_content_setting_values.media_stream_mic': 2,
        'profile.default_content_setting_values.media_stream_camera': 2,
    })
    chrome_options.binary_location = "/usr/bin/google-chrome"
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    service = Service(executable_path="/usr/bin/chromedriver")
    chromebrowser = webdriver.Chrome(options=chrome_options, service=service)
    chromebrowser.set_window_size(1440, 900)
    # Bind the interactive control socket BEFORE the (potentially long) page
    # analysis so the file exists immediately. The backend only waits for the
    # socket to appear within analyzer_timeout; binding late (after page load +
    # screenshots) risked that wait expiring, which killed the container and
    # left a stale socket the frontend could not connect to (Errno 111).
    # A bound+listening socket queues any early connect in its backlog until
    # the accept loop starts at the end of this function.
    interactive_server = None
    if parsed.get('interactive'):
        interactive_server = create_interactive_socket(parsed)
    # Bound how long a navigation may block. Without this, get() uses Chrome's
    # 300s default and a slow target (especially over Tor) stalls the whole
    # analysis past the worker/celery time limits. On timeout get() raises and
    # we simply screenshot whatever loaded. page_load_strategy='eager' returns
    # at DOMContentLoaded instead of waiting for every sub-resource/tracker.
    try:
        chromebrowser.set_page_load_timeout(int(parsed["url_timeout"]))
    except BaseException:
        pass
    if parsed["no_redirect"]:
        chromebrowser.implicitly_wait(0.1)
        try:
            chromebrowser.get(parsed["buffer"])
        except BaseException:
            pass
    else:
        chromebrowser.implicitly_wait(int(parsed["url_timeout"]))
        try:
            chromebrowser.get(parsed["buffer"])
        except BaseException:
            pass
    if parsed.get('block_cookies'):
        dismiss_cookie_banners(chromebrowser, settle=0 if parsed.get('interactive') else 0.6)
    performance_logs = chromebrowser.get_log('performance')
    get_cert(parsed, extracted_table)
    get_all_links(chromebrowser.page_source, extracted_table)
    get_all_scripts(chromebrowser.page_source, extracted_table)
    extract_phishing_heuristics(chromebrowser, parsed, extracted_table)
    should_take_normal = parsed.get('take_screenshot', False) or (parsed.get('take_screenshot') is None and parsed.get('take_full_screenshot'))
    should_take_full = parsed.get('take_full_screenshot', False)
    if should_take_full:
        take_full_screen_shot(chromebrowser, screenshot_table)
    if should_take_normal:
        take_normal_screen_shot(chromebrowser, screenshot_table)
    parse_ouput(performance_logs, analyzer_table)
    make_network(analyzer_table, network_table)
    if parsed.get('interactive') and interactive_server is not None:
        # Signal the backend that the initial analysis (screenshots, cert,
        # network graph, …) is fully written to the shared output, so it can
        # build a COMPLETE report before we hand off to the interactive loop.
        # The control socket is bound early (for connection reliability), so it
        # cannot double as the "analysis done" signal any more.
        signal_analysis_done(parsed)
        serve_interactive(interactive_server, chromebrowser, parsed, analyzer_db)
    chromebrowser.quit()

    if ffmpeg_proc is not None:
        try:
            print("[SandBox] Finalizing video recording...", flush=True)
            try:
                ffmpeg_proc.communicate(input=b'q', timeout=4)
            except Exception:
                ffmpeg_proc.send_signal(signal.SIGINT)
                ffmpeg_proc.wait(timeout=3)
        except Exception as e:
            print(f"[SandBox] Warning stopping ffmpeg: {e}", flush=True)
            try:
                ffmpeg_proc.kill()
            except Exception:
                pass

    if parsed.get('interactive'):
        try:
            task_dir = os.path.join(parsed['locations']['box_output'], parsed['task'])
            session_meta_path = os.path.join(task_dir, "vnc_session.json")
            has_vid = os.path.exists(video_file) and os.path.getsize(video_file) > 1000
            with open(session_meta_path, "w") as smf:
                smf.write(dumps({
                    "task": parsed['task'],
                    "vnc_port": parsed.get('vnc_port'),
                    "status": "ended",
                    "record_vnc": bool(parsed.get('record_vnc')),
                    "has_video": has_vid
                }))
        except Exception as e:
            print(f"[SandBox] Warning updating vnc_session.json: {e}", flush=True)

    for p in vnc_processes:
        try:
            p.terminate()
            p.wait(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    DISPLAY.stop()
    print("[SandBox] main logic done")


def signal_analysis_done(parsed):
    '''
    write a marker file once the initial analysis output is saved, so the
    backend knows it is safe to build the report even though the interactive
    container stays alive afterwards
    '''
    import os
    try:
        marker = os.path.join(parsed['locations']['box_output'], parsed['task'], "analysis.done")
        with open(marker, 'w') as fh:
            fh.write("done")
        print("[SandBox] Analysis-complete marker written", flush=True)
    except Exception as e:
        print(f"[SandBox] signal_analysis_done failed: {e}", flush=True)


def create_interactive_socket(parsed):
    '''
    create, bind and listen the interactive control socket early so the file
    exists before the page analysis runs. Returns the listening server socket,
    or None on failure. Connections that arrive before serve_interactive() runs
    queue in the listen backlog and are handled once accept() is called.
    '''
    import socket
    import os

    try:
        task_id = parsed['task']
        socket_dir = os.path.join(parsed['locations']['box_output'], task_id)
        if not os.path.exists(socket_dir):
            os.makedirs(socket_dir, exist_ok=True)
        socket_path = os.path.join(socket_dir, "control.sock")

        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
            except Exception:
                pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path)
        server.listen(8)
        print(f"[SandBox] Interactive Unix socket bound at {socket_path}", flush=True)
        return server
    except Exception as e:
        print(f"[SandBox] create_interactive_socket failed: {e}", flush=True)
        return None


def serve_interactive(server, driver, parsed, analyzer_db):
    import socket
    import os
    import json
    import time
    from base64 import b64encode

    socket_path = os.path.join(parsed['locations']['box_output'], parsed['task'], "control.sock")
    # idle timeout for the interactive session, chosen by the user (default 5 min)
    idle_timeout = float(parsed.get('interactive_timeout', 300) or 300)
    server.settimeout(idle_timeout)

    print(f"[SandBox] Interactive Unix socket server accepting connections (idle timeout {int(idle_timeout)}s)", flush=True)
    screenshot_table = analyzer_db.table('screenshot_table')
    last_interaction_time = time.time()

    while True:
        try:
            if time.time() - last_interaction_time > idle_timeout:
                print("[SandBox] Interactive session timed out.", flush=True)
                break

            server.settimeout(max(1.0, idle_timeout - (time.time() - last_interaction_time)))
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
                
            conn.settimeout(10.0)
            data = conn.recv(4096)
            if not data:
                conn.close()
                continue
                
            try:
                req = json.loads(data.decode('utf-8'))
                action = req.get('action')
                print(f"[SandBox] Received action: {action}", flush=True)
                
                if action == 'click':
                    x = int(req.get('x', 0))
                    y = int(req.get('y', 0))
                    is_full = req.get('is_full', False)
                    
                    if is_full:
                        scroll_y = max(0, y - 300)
                        driver.execute_script("window.scrollTo(0, arguments[0]);", scroll_y)
                        time.sleep(0.2)
                        actual_y = y - driver.execute_script("return window.pageYOffset;")
                        actual_x = x
                    else:
                        actual_x = x
                        actual_y = y
                        
                    viewport = driver.execute_script(
                        "return [window.innerWidth, window.innerHeight];")
                    actual_x = max(0, min(actual_x, viewport[0] - 1))
                    actual_y = max(0, min(actual_y, viewport[1] - 1))

                    print(f"[SandBox] Dispatching mouse click at ({actual_x}, {actual_y})", flush=True)
                    try:
                        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                            "type": "mouseMoved",
                            "x": actual_x, "y": actual_y})
                        time.sleep(0.1)
                        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                            "type": "mousePressed",
                            "x": actual_x, "y": actual_y,
                            "button": "left", "clickCount": 1})
                        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                            "type": "mouseReleased",
                            "x": actual_x, "y": actual_y,
                            "button": "left", "clickCount": 1})
                    except Exception as e:
                        print(f"[SandBox] CDP click failed: {e}", flush=True)
                    time.sleep(1.0)
                    
                elif action == 'scroll':
                    amount = int(req.get('amount', 0))
                    driver.execute_script("window.scrollBy(0, arguments[0]);", amount)
                    time.sleep(0.2)
                    
                elif action == 'close':
                    print("[SandBox] Close requested. Capturing final state & shutting down interactive server.", flush=True)
                    try:
                        screenshot = driver.get_screenshot_as_png()
                        screenshot_table.truncate()
                        screenshot_table.insert({'normal_image': hexlify(screenshot).decode('utf-8')})
                        img_base64 = b64encode(screenshot).decode('utf-8')
                        conn.sendall(json.dumps({"status": "ok", "message": "closed", "screenshot": img_base64}).encode('utf-8'))
                    except Exception as se:
                        conn.sendall(json.dumps({"status": "ok", "message": "closed"}).encode('utf-8'))
                    conn.close()
                    break
                    
                screenshot = driver.get_screenshot_as_png()
                screenshot_table.truncate()
                
                take_full = parsed.get('take_full_screenshot', False)
                full_img_base64 = None
                
                if take_full:
                    try:
                        element = driver.find_element(By.TAG_NAME, 'html')
                        full_screenshot = element.get_screenshot_as_png()
                        screenshot_table.insert({
                            'normal_image': hexlify(screenshot).decode('utf-8'),
                            'full_image': hexlify(full_screenshot).decode('utf-8')
                        })
                        full_img_base64 = b64encode(full_screenshot).decode('utf-8')
                    except Exception as fe:
                        print(f"[SandBox] Interactive full screenshot failed: {fe}", flush=True)
                        screenshot_table.insert({'normal_image': hexlify(screenshot).decode('utf-8')})
                else:
                    screenshot_table.insert({'normal_image': hexlify(screenshot).decode('utf-8')})
                
                img_base64 = b64encode(screenshot).decode('utf-8')
                response = {
                    "status": "ok",
                    "screenshot": img_base64
                }
                if full_img_base64:
                    response["full_screenshot"] = full_img_base64
                    
                conn.sendall(json.dumps(response).encode('utf-8'))
                last_interaction_time = time.time()
                
            except Exception as ex:
                print(f"[SandBox] Error processing request: {ex}", flush=True)
                try:
                    conn.sendall(json.dumps({"status": "error", "message": str(ex)}).encode('utf-8'))
                except:
                    pass
            finally:
                conn.close()
                
        except Exception as e:
            print(f"[SandBox] Socket server exception: {e}", flush=True)
            break
            
    server.close()
    if os.path.exists(socket_path):
        try:
            os.remove(socket_path)
        except Exception:
            pass
    print("[SandBox] Interactive socket server stopped.", flush=True)
