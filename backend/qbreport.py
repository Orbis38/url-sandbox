'''
    __G__ = "(G)bd249ce4"
    backend -> report
'''

from json import dumps
from base64 import b64encode
from datetime import datetime
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

    analyzer_path = "{}{}{}".format(parsed['locations']['box_output'], parsed['task'], parsed['locations']['analyzer_logs'])
    sniffer_path = "{}{}{}".format(parsed['locations']['box_output'], parsed['task'], parsed['locations']['sniffer_logs'])

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
                <div class="up-interactive-actions">
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
                var VNC_PORT = {vnc_port};
                var host = window.location.hostname || 'localhost';
                var proto = window.location.protocol;
                var vncUrl = proto + '//' + host + ':' + VNC_PORT + '/vnc.html?autoconnect=true&resize=scale&reconnect=true';

                function initVnc() {{
                    var $ = window.jQuery;
                    $('#novnc-frame').attr('src', vncUrl);
                    $('#btn-newtab').attr('href', vncUrl);
                }}

                window.toggleVncFullscreen = function() {{
                    var el = document.getElementById('vnc-container');
                    if (!document.fullscreenElement) {{
                        if (el.requestFullscreen) {{ el.requestFullscreen(); }}
                        else if (el.webkitRequestFullscreen) {{ el.webkitRequestFullscreen(); }}
                    }} else {{
                        if (document.exitFullscreen) {{ document.exitFullscreen(); }}
                    }}
                }};

                window.finishLiveSession = function() {{
                    var $ = window.jQuery;
                    if (!confirm('Finish interactive session and save the final report state?')) return;
                    var btn = $('#btn-finish');
                    btn.prop('disabled', true).text('Saving final state…');
                    $('#live-status-title').text('Session terminating…');
                    $('#live-indicator-dot').css('background', '#f59e0b');

                    $.ajax({{
                        url: '/live_interact/' + TASK,
                        type: 'POST',
                        contentType: 'application/json',
                        data: JSON.stringify({{ action: 'close' }}),
                        success: function(resp) {{
                            $('#live-status-title').text('Session completed.');
                            $('#live-indicator-dot').css('background', '#64748b');
                            setTimeout(function() {{
                                window.location.reload();
                            }}, 1000);
                        }},
                        error: function() {{
                            window.location.reload();
                        }}
                    }});
                }};

                (function ready() {{
                    if (typeof window.jQuery === 'undefined') {{ return setTimeout(ready, 50); }}
                    window.jQuery(function () {{ initVnc(); }});
                }})();
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
