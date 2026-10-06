'''
    __G__ = "(G)bd249ce4"
    backend -> report
'''

from json import dumps
from base64 import b64encode
from datetime import datetime
from os import path
from tinydb import TinyDB
from binascii import unhexlify
from jinja2 import Template, Environment, FileSystemLoader
from shared.logger import log_string, ignore_exception
from shared.settings import defaultdb
from shared.mongodbconn import add_item_fs, find_item


def pretty_json(value):
    '''
    object to json
    '''
    return dumps(value, indent=4)


def make_json_table(env, data, header) -> str:
    '''
    render json html table
    '''
    parsed_header = header.replace(' ', '_')
    temp = """
    <div class="tablewrapper">
    <table>
        <thead>
            <tr>
                <th colspan="1" onclick=toggle_class(".table-{{ parsed_header }}")>{{ header }}</th>
            </tr>
        </thead>
        <tbody class="table-{{ parsed_header }}" style="display:none";>
           {%- for row in data -%}
               <tr>
                <td><pre>{{ row | pretty_json }}</pre></td>
               </tr>
           {%- endfor -%}
        </tbody>
    </table>
    </div>"""

    result = env.from_string(temp).render(header=header, parsed_header=parsed_header, data=data)
    return result


def make_json_table_no_loop(env, data, header) -> str:
    '''
    render json html table
    '''
    parsed_header = header.replace(' ', '_')
    temp = """
    <div class="tablewrapper">
    <table>
        <thead>
            <tr>
                <th colspan="1" onclick=toggle_class(".table-{{ parsed_header }}")>{{ header }}</th>
            </tr>
        </thead>
        <tbody class="table-{{ parsed_header }}" style="display:none";>
               <tr>
                <td><pre>{{ data | pretty_json }}</pre></td>
               </tr>
        </tbody>
    </table>
    </div>"""

    result = env.from_string(temp).render(header=header, parsed_header=parsed_header, data=data)
    return result


def make_text_table(env, data, header) -> str:
    '''
    render text html table
    '''
    parsed_header = header.replace(' ', '_')
    temp = """
    <div class="tablewrapper">
    <table>
        <thead>
            <tr>
                <th colspan="1" onclick=toggle_class(".table-{{ parsed_header }}")>{{ header }}</th>
            </tr>
        </thead>
        <tbody class="table-{{ parsed_header }}" style="display:none";>
           {%- for row in data -%}
               <tr>
                <td>{{ row }}</td>
               </tr>
           {%- endfor -%}
        </tbody>
    </table>
    </div>"""

    result = env.from_string(temp).render(header=header, parsed_header=parsed_header, data=data)
    return result


def make_image_table_base64(env, data, header) -> str:
    '''
    render image inside html table
    '''
    parsed_header = header.replace(' ', '_')
    temp = """
    <div class="tablewrapper">
    <table>
        <thead>
            <tr>
                <th colspan="1" onclick=toggle_class(".table-{{ parsed_header }}")>{{ header }}</th>
            </tr>
        </thead>
        <tbody class="table-{{ parsed_header }}" style="display:none";>
               <tr>
                    <td><img class="fullsize" src="{{ data }}" /></td>
                </tr>
        </tbody>
    </table>
    </div>"""
    result = env.from_string(temp).render(header=header, parsed_header=parsed_header, data=data)
    return result


ENV_JINJA2 = Environment(autoescape=True, loader=FileSystemLoader('/tmp'), trim_blocks=True, lstrip_blocks=True)
ENV_JINJA2.filters['pretty_json'] = pretty_json


def make_report(parsed):
    '''
    make the html table
    '''
    table = ""
    full_table = ""

    analyzer_db = None
    sniffer_db = None

    task_dir = path.join(parsed['locations']['box_output'], parsed['task'])
    analyzer_path = path.join(task_dir, parsed['task'] + parsed['locations']['analyzer_logs'])
    sniffer_path = path.join(task_dir, parsed['task'] + parsed['locations']['sniffer_logs'])

    analyzer_db = TinyDB(analyzer_path)
    sniffer_db = TinyDB(sniffer_path)

    with open(analyzer_path) as file:
        temp_id = add_item_fs(defaultdb["dbname"], defaultdb["reportscoll"], file.read(), parsed['task'], None, parsed['task'], "application/json", datetime.now())

    # Build & store AI-ready multimodal summary for Playbooks & local LLMs (Gemma)
    with ignore_exception(Exception):
        extracted_table = analyzer_db.table('extracted_table')
        heuristics_item = extracted_table.search(lambda x: x if 'ai_heuristics' in x else 0)
        heuristics = heuristics_item[0]['ai_heuristics'] if heuristics_item else {}

        cert_item = extracted_table.search(lambda x: x if 'Certificate' in x else 0)
        cert = cert_item[0]['Certificate'] if cert_item else {}

        dns_item = extracted_table.search(lambda x: x if 'dns_records' in x else 0)
        dns = dns_item[0]['dns_records'] if dns_item else []

        screenshot_table = analyzer_db.table('screenshot_table')
        ai_img_item = screenshot_table.search(lambda x: x if 'ai_image_jpeg' in x else 0)
        normal_img_item = screenshot_table.search(lambda x: x if 'normal_image' in x else 0)

        ai_jpeg_b64 = ""
        if ai_img_item:
            ai_jpeg_b64 = b64encode(unhexlify(ai_img_item[0]['ai_image_jpeg'].encode('utf-8'))).decode('utf-8')
        elif normal_img_item:
            try:
                from PIL import Image
                import io
                raw_png = unhexlify(normal_img_item[0]['normal_image'].encode('utf-8'))
                img = Image.open(io.BytesIO(raw_png)).convert('RGB')
                img.thumbnail((1280, 800), Image.Resampling.LANCZOS)
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=82, optimize=True)
                ai_jpeg_b64 = b64encode(buf.getvalue()).decode('utf-8')
            except Exception:
                ai_jpeg_b64 = b64encode(unhexlify(normal_img_item[0]['normal_image'].encode('utf-8'))).decode('utf-8')

        ai_summary_dict = {
            "task_id": parsed['task'],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "url_analysis": {
                "submitted_url": heuristics.get('submitted_url', parsed.get('buffer', '')),
                "final_url": heuristics.get('final_url', parsed.get('buffer', '')),
                "initial_domain": heuristics.get('initial_domain', parsed.get('domain', '')),
                "final_domain": heuristics.get('final_domain', parsed.get('domain', '')),
                "redirected": heuristics.get('redirected', False),
                "is_punycode_homograph": heuristics.get('is_punycode', False)
            },
            "page_content": {
                "page_title": heuristics.get('page_title', ''),
                "has_password_field": heuristics.get('has_password_field', False),
                "password_field_count": heuristics.get('password_field_count', 0),
                "has_credential_inputs": heuristics.get('has_credential_inputs', False),
                "has_credit_card_inputs": heuristics.get('has_credit_card_inputs', False),
                "form_action_targets": heuristics.get('form_actions', []),
                "detected_brands": heuristics.get('detected_brands', []),
                "brand_domain_mismatch": heuristics.get('brand_domain_mismatch', False)
            },
            "ssl_certificate": {
                "issuer": [list(x.values())[0] for x in cert.get('Issuer', []) if isinstance(x, dict)] or cert.get('Issuer', ''),
                "subject": [list(x.values())[0] for x in cert.get('Subjects', []) if isinstance(x, dict)] or cert.get('Subjects', ''),
                "valid_from": cert.get('Valid From', ''),
                "valid_until": cert.get('Valid Until', ''),
                "expired": cert.get('Expired', False)
            },
            "dns_records": dns,
            "threat_indicators": heuristics.get('threat_indicators', []),
            "screenshot_base64": f"data:image/jpeg;base64,{ai_jpeg_b64}" if ai_jpeg_b64 else "",
            "screenshot_url": f"/api/v1/tasks/{parsed['task']}/screenshot"
        }
        add_item_fs(defaultdb["dbname"], defaultdb["reportscoll"], dumps(ai_summary_dict), parsed['task'], None, parsed['task'], "application/json; type=ai_summary", datetime.now())
        log_string("Saved AI multimodal summary to GridFS", task=parsed['task'])

    # Interactive intro note renders above the screenshot.
    if parsed.get('interactive'):
        table += "<!--INTERACTIVE_INTRO-->"

    with ignore_exception(Exception):
        screenshot_table = analyzer_db.table('screenshot_table')
        item = screenshot_table.search(lambda x: x if 'normal_image' in x else 0)
        if item:
            bimage = b64encode(unhexlify(item[0]['normal_image'].encode('utf-8')))
            img_base64 = "data:image/jpeg;base64, {}".format(bimage.decode("utf-8", errors="ignore"))
            table += make_image_table_base64(ENV_JINJA2, img_base64, "Screenshot")
            log_string("Parsed normal screenshot", task=parsed['task'])

    # Interactive scroll controls render directly under the screenshot.
    if parsed.get('interactive'):
        table += "<!--INTERACTIVE_CONTROLS-->"

    with ignore_exception(Exception):
        screenshot_table = analyzer_db.table('screenshot_table')
        item = screenshot_table.search(lambda x: x if 'full_image' in x else 0)
        if item:
            bimage = b64encode(unhexlify(item[0]['full_image'].encode('utf-8')))
            img_base64 = "data:image/jpeg;base64, {}".format(bimage.decode("utf-8", errors="ignore"))
            table += make_image_table_base64(ENV_JINJA2, img_base64, "Full Screenshot")
            log_string("Parsed full screenshot", task=parsed['task'])

    with ignore_exception(Exception):
        network_table = analyzer_db.table('network_table')
        item = network_table.search(lambda x: x if 'circular_layout' in x else 0)
        if item:
            bimage = b64encode(unhexlify(item[0]['circular_layout'].encode('utf-8')))
            img_base64 = "data:image/jpeg;base64, {}".format(bimage.decode("utf-8", errors="ignore"))
            table += make_image_table_base64(ENV_JINJA2, img_base64, "Network Graph")
            log_string("Parsed Network Graph", task=parsed['task'])

    with ignore_exception(Exception):
        words_table = analyzer_db.table('extracted_table')
        item = words_table.search(lambda x: x if 'dns_records' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["dns_records"], "DNS Records")

    with ignore_exception(Exception):
        words_table = analyzer_db.table('extracted_table')
        item = words_table.search(lambda x: x if 'Request_Headers' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["Request_Headers"], "Request Headers")

    with ignore_exception(Exception):
        words_table = analyzer_db.table('extracted_table')
        item = words_table.search(lambda x: x if 'Response_Headers' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["Response_Headers"], "Response Headers")

    with ignore_exception(Exception):
        words_table = analyzer_db.table('extracted_table')
        item = words_table.search(lambda x: x if 'Certificate' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["Certificate"], "Certificate")

    with ignore_exception(Exception):
        words_table = analyzer_db.table('words_table')
        item = words_table.search(lambda x: x if 'all_words' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item, "OCR Words")

    with ignore_exception(Exception):
        extracted_table = analyzer_db.table('extracted_table')
        item = extracted_table.search(lambda x: x if 'extracted_links' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["extracted_links"], "Extracted links")

    with ignore_exception(Exception):
        extracted_table = analyzer_db.table('extracted_table')
        item = extracted_table.search(lambda x: x if 'extracted_scripts' in x else 0)
        if item:
            table += make_json_table_no_loop(ENV_JINJA2, item[0]["extracted_scripts"], "Extracted scripts")

    with ignore_exception(Exception):
        extracted_table = analyzer_db.table('extracted_table')
        heuristics_item = extracted_table.search(lambda x: x if 'ai_heuristics' in x else 0)
        if heuristics_item:
            table += make_json_table_no_loop(ENV_JINJA2, heuristics_item[0]['ai_heuristics'], "Security & Phishing Heuristics")

    with ignore_exception(Exception):
        analyzer_table = analyzer_db.table('analyzer_table')
        if len(analyzer_table.all()) > 0:
            table += make_json_table(ENV_JINJA2, analyzer_table.all(), "Browser")

    with ignore_exception(Exception):
        sniffer_table = sniffer_db.table('sniffer_table')
        if len(sniffer_table.all()) > 0:
            table += make_json_table_no_loop(ENV_JINJA2, sniffer_table.all(), "Sniffer")

    if parsed.get('interactive'):
        vnc_port = int(parsed.get('vnc_port', 6080) or 6080)
        widget_html = f"""
        <style>
            .up-interactive-widget {{
                margin: 0 0 24px 0;
                border: 1px solid rgba(124,140,248,0.35);
                border-radius: 12px;
                background: #111420;
                box-shadow: 0 6px 24px rgba(0,0,0,0.4);
                overflow: hidden;
            }}
            .up-interactive-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 10px 16px;
                background: #171b2e;
                border-bottom: 1px solid rgba(124,140,248,0.2);
                flex-wrap: wrap;
                gap: 10px;
            }}
            .up-live-badge {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: #e2e8f0;
                font-weight: 600;
                font-size: 13px;
            }}
            .up-live-dot {{
                width: 10px;
                height: 10px;
                border-radius: 50%;
                background: #22c55e;
                box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.3);
                animation: up-pulse 2s infinite;
            }}
            @keyframes up-pulse {{
                0% {{ box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.5); }}
                70% {{ box-shadow: 0 0 0 8px rgba(34, 197, 94, 0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }}
            }}
            .up-interactive-actions {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
            .up-btn-primary, .up-btn-secondary, .up-btn-danger {{
                display: inline-flex;
                align-items: center;
                gap: 5px;
                font-family: inherit;
                font-size: 12px;
                font-weight: 600;
                padding: 6px 12px;
                border-radius: 6px;
                border: none;
                cursor: pointer;
                transition: all .15s ease-in-out;
                text-decoration: none;
            }}
            .up-btn-primary {{ background: #6366f1; color: #fff; }}
            .up-btn-primary:hover {{ background: #4f46e5; }}
            .up-btn-secondary {{ background: #334155; color: #cbd5e1; }}
            .up-btn-secondary:hover {{ background: #475569; color: #fff; }}
            .up-btn-danger {{ background: #ef4444; color: #fff; }}
            .up-btn-danger:hover {{ background: #dc2626; }}
            .up-vnc-frame-container {{
                position: relative;
                width: 100%;
                height: 720px;
                background: #000;
            }}
            .up-vnc-frame-container iframe {{
                width: 100%;
                height: 100%;
                border: none;
                display: block;
            }}
            .up-session-ended-box {{
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 420px;
                background: #090d16;
                color: #94a3b8;
                text-align: center;
                padding: 32px 20px;
            }}
            .up-session-ended-icon {{
                width: 54px;
                height: 54px;
                border-radius: 50%;
                background: rgba(99, 102, 241, 0.15);
                border: 2px solid #6366f1;
                color: #818cf8;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
                margin-bottom: 14px;
            }}
        </style>

        <div class="up-interactive-widget" id="interactive-widget">
            <div class="up-interactive-header">
                <div class="up-live-badge">
                    <span class="up-live-dot" id="live-indicator-dot"></span>
                    <span id="live-status-title">Live Interactive Browser (30 FPS &bull; 1440&times;900)</span>
                    <span id="live-session-info" style="color: #94a3b8; font-weight: normal; font-size: 12px; margin-left: 6px;">
                        Direct navigation: scroll, click, and type in real time
                    </span>
                </div>
                <div class="up-interactive-actions" id="interactive-actions">
                    <button type="button" class="up-btn-secondary" id="btn-fullscreen" onclick="toggleVncFullscreen()">⛶ Fullscreen</button>
                    <a href="#" target="_blank" class="up-btn-secondary" id="btn-newtab">⎘ Open in New Tab</a>
                    <button type="button" class="up-btn-danger" id="btn-finish" onclick="finishLiveSession()">✓ Finish Session</button>
                </div>
            </div>
            <div class="up-vnc-frame-container" id="vnc-container">
                <iframe id="novnc-frame" allow="fullscreen; clipboard-read; clipboard-write"></iframe>
            </div>
        </div>

        <script>
            (function () {{
                var TASK = '{parsed['task']}';
                var FALLBACK_PORT = {vnc_port};
                var host = window.location.hostname || 'localhost';
                var proto = window.location.protocol;
                var pollInterval = null;

                function renderSessionEnded(info) {{
                    if (pollInterval) {{ clearInterval(pollInterval); pollInterval = null; }}
                    var dot = document.getElementById('live-indicator-dot');
                    if (dot) {{ dot.style.background = '#64748b'; dot.style.boxShadow = 'none'; dot.style.animation = 'none'; }}
                    var title = document.getElementById('live-status-title');
                    if (title) {{ title.textContent = 'Sessione VNC Conclusa'; }}
                    var sInfo = document.getElementById('live-session-info');
                    if (sInfo) {{ sInfo.innerHTML = '<span style="color:#64748b;">Analisi: ' + TASK.substring(0, 8) + '</span>'; }}
                    var actions = document.getElementById('interactive-actions');
                    if (actions) {{ actions.style.display = 'none'; }}
                    var frame = document.getElementById('novnc-frame');
                    if (frame) {{ frame.remove(); }}

                    var videoBlock = '';
                    if (info && (info.has_video || info.video_url)) {{
                        var vUrl = info.video_url || ('/api/v1/tasks/' + TASK + '/video');
                        videoBlock = '<div style="margin-top:24px;width:100%;max-width:800px;text-align:left;">' +
                            '<div style="font-weight:600;color:#f1f5f9;margin-bottom:8px;font-size:14px;display:flex;align-items:center;justify-content:space-between;">' +
                                '<span>🎥 Video Registrazione Sessione VNC</span>' +
                                '<a href="' + vUrl + '" download="' + TASK + '_session.mp4" class="up-btn-secondary" style="font-size:11px;padding:3px 8px;">⬇ Scarica MP4</a>' +
                            '</div>' +
                            '<video controls style="width:100%;border-radius:8px;background:#000;border:1px solid #334155;max-height:480px;" preload="metadata">' +
                                '<source src="' + vUrl + '" type="video/mp4">' +
                                'Il browser non supporta la riproduzione del video.' +
                            '</video>' +
                        '</div>';
                    }}

                    var container = document.getElementById('vnc-container');
                    if (container) {{
                        container.innerHTML =
                            '<div class="up-session-ended-box">' +
                                '<div class="up-session-ended-icon">✓</div>' +
                                '<h4 style="color:#f1f5f9;margin-bottom:8px;font-size:18px;font-weight:600;">Sessione VNC Conclusa</h4>' +
                                '<p style="color:#94a3b8;font-size:13px;max-width:540px;line-height:1.5;margin-bottom:0;">' +
                                    'La sessione interattiva VNC per questa analisi <code style="color:#818cf8;background:#1e293b;padding:2px 6px;border-radius:4px;">' + TASK + '</code> è terminata. Il browser è stato chiuso e lo stato finale è salvato.' +
                                '</p>' +
                                videoBlock +
                            '</div>';
                    }}
                }}

                function checkStatus() {{
                    fetch('/live_interact/' + TASK + '/status', {{
                        headers: {{ 'Accept': 'application/json' }},
                        credentials: 'same-origin'
                    }})
                    .then(function(r) {{ return r.json(); }})
                    .then(function(resp) {{
                        if (resp && (resp.status === 'ended' || resp.active === false)) {{
                            renderSessionEnded(resp);
                        }}
                    }})
                    .catch(function() {{
                        // Ignore transient network errors
                    }});
                }}

                function initSession() {{
                    var frame = document.getElementById('novnc-frame');
                    var newtab = document.getElementById('btn-newtab');
                    var sInfo = document.getElementById('live-session-info');

                    fetch('/live_interact/' + TASK + '/status', {{
                        headers: {{ 'Accept': 'application/json' }},
                        credentials: 'same-origin'
                    }})
                    .then(function(r) {{ return r.json(); }})
                    .then(function(resp) {{
                        if (resp && (resp.status === 'ended' || resp.active === false)) {{
                            renderSessionEnded(resp);
                            return;
                        }}
                        if (!resp || !resp.vnc_token || !resp.vnc_port) {{
                            if (sInfo) {{ sInfo.textContent = 'Session unavailable'; }}
                            return;
                        }}
                        var port = resp.vnc_port;
                        var socketPath = encodeURIComponent('websockify?token=' + resp.vnc_token);
                        var vncUrl = proto + '//' + host + ':' + port + '/vnc.html?autoconnect=true&resize=scale&reconnect=false&path=' + socketPath;
                        if (frame) {{ frame.src = vncUrl; }}
                        if (newtab) {{ newtab.href = vncUrl; }}
                        if (sInfo) {{ sInfo.innerHTML = '<span style="color:#818cf8;font-weight:600;">Porta ' + port + '</span> &bull; Analisi: ' + TASK.substring(0, 8); }}
                        pollInterval = setInterval(checkStatus, 4000);
                    }})
                    .catch(function() {{
                        if (sInfo) {{ sInfo.textContent = 'Unable to authorize session'; }}
                    }});
                }}

                window.toggleVncFullscreen = function() {{
                    var el = document.getElementById('vnc-container');
                    if (!el) return;
                    if (!document.fullscreenElement) {{
                        if (el.requestFullscreen) {{ el.requestFullscreen(); }}
                        else if (el.webkitRequestFullscreen) {{ el.webkitRequestFullscreen(); }}
                    }} else {{
                        if (document.exitFullscreen) {{ document.exitFullscreen(); }}
                    }}
                }};

                window.finishLiveSession = function() {{
                    if (!confirm('Confermi di voler terminare la sessione interattiva VNC e salvare lo stato finale?')) return;
                    var btn = document.getElementById('btn-finish');
                    if (btn) {{
                        btn.disabled = true;
                        btn.textContent = 'Chiusura in corso…';
                    }}
                    var title = document.getElementById('live-status-title');
                    if (title) {{ title.textContent = 'Chiusura sessione…'; }}
                    var dot = document.getElementById('live-indicator-dot');
                    if (dot) {{
                        dot.style.background = '#f59e0b';
                        dot.style.boxShadow = '0 0 8px #f59e0b';
                    }}

                    if (pollInterval) {{ clearInterval(pollInterval); pollInterval = null; }}

                    var frame = document.getElementById('novnc-frame');
                    if (frame) {{ frame.remove(); }}

                    var container = document.getElementById('vnc-container');
                    if (container) {{
                        container.innerHTML =
                            '<div class="up-session-ended-box">' +
                                '<div class="up-session-ended-icon" style="border-color:#f59e0b;color:#f59e0b;">⏳</div>' +
                                '<h4 style="color:#f1f5f9;margin-bottom:8px;font-size:18px;">Salvataggio stato finale…</h4>' +
                                '<p style="color:#94a3b8;font-size:13px;">Finalizzazione della sessione VNC e generazione del report.</p>' +
                            '</div>';
                    }}

                    fetch('/live_interact/' + TASK, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        credentials: 'same-origin',
                        body: JSON.stringify({{ action: 'close' }})
                    }})
                    .then(function() {{
                        setTimeout(function() {{
                            window.location.reload();
                        }}, 1200);
                    }})
                    .catch(function() {{
                        setTimeout(function() {{
                            window.location.reload();
                        }}, 1200);
                    }});
                }};

                if (document.readyState === 'loading') {{
                    document.addEventListener('DOMContentLoaded', initSession);
                }} else {{
                    initSession();
                }}
            }})();
        </script>
        """

        table = table.replace("<!--INTERACTIVE_INTRO-->", widget_html)
        table = table.replace("<!--INTERACTIVE_CONTROLS-->", "")

    all_logs = find_item(defaultdb["dbname"], defaultdb["taskdblogscoll"], {'task': parsed['task']})
    if all_logs:
        full_table = make_text_table(ENV_JINJA2, all_logs['logs'], "Logs")
        log_string("Adding logs", task=parsed['task'])

    full_table += table
    if len(full_table) == 0:
        full_table = "Error"

    with open("template.html") as file:
        rendered = Template(file.read()).render(title=parsed['task'], content=full_table)
        temp_id = add_item_fs(defaultdb["dbname"], defaultdb["reportscoll"], rendered, parsed['task'], None, parsed['task'], "text/html", datetime.now())

    temp_id = add_item_fs(defaultdb["dbname"], defaultdb["taskfileslogscoll"], "\n".join(all_logs['logs']), "log", None, parsed['task'], "text/plain", datetime.now())
