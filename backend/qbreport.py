'''
    __G__ = "(G)bd249ce4"
    backend -> report
'''

from os import path
from json import loads, dumps, JSONEncoder
from pickle import load as pload
from base64 import b64encode
from datetime import datetime
from tinydb import TinyDB, Query
from binascii import unhexlify
from jinja2 import Template, Environment, FileSystemLoader
from shared.logger import log_string, ignore_exception
from shared.settings import defaultdb
from shared.mongodbconn import add_item_fs, find_item


class ComplexEncoder(JSONEncoder):
    '''
    this will be used to encode objects
    '''

    def default(self, obj):
        '''
        override default
        '''
        if not isinstance(obj, str):
            return str(obj)
        return JSONEncoder.default(self, obj)


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
        analyzer_table = analyzer_db.table('analyzer_table')
        if len(analyzer_table.all()) > 0:
            table += make_json_table(ENV_JINJA2, analyzer_table.all(), "Browser")

    with ignore_exception(Exception):
        sniffer_table = sniffer_db.table('sniffer_table')
        if len(sniffer_table.all()) > 0:
            table += make_json_table_no_loop(ENV_JINJA2, sniffer_table.all(), "Sniffer")

    if parsed.get('interactive'):
        intro_html = """
        <div style="display:flex;align-items:flex-start;gap:10px;margin:0 0 14px;padding:12px 16px;border:1px solid rgba(124,140,248,0.4);border-radius:10px;background:var(--up-accent-soft,rgba(124,140,248,0.16));color:var(--up-accent-text,#aab4ff);font-size:13px;line-height:1.45">
            <span style="flex-shrink:0;width:8px;height:8px;margin-top:5px;border-radius:50%;background:var(--up-green,#5ad19b);box-shadow:0 0 0 3px rgba(90,209,155,0.2)"></span>
            <div><strong>This session is live and interactive.</strong> Click anywhere on the screenshot to click that exact spot inside the sandbox, or use the scroll buttons below it to move down the page. The screenshot refreshes after every action.</div>
        </div>
        """

        controls_html = """
        <style>
            #interactive-controls .up-live-btn{display:inline-flex;align-items:center;gap:6px;background:var(--up-accent,#5b6ef5);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-family:inherit;font-weight:600;font-size:12.5px;cursor:pointer;transition:background .15s}
            #interactive-controls .up-live-btn:hover{background:oklch(0.67 0.19 264)}
            #interactive-controls .up-live-btn:active{background:oklch(0.57 0.19 264)}
        </style>
        <div id="interactive-controls" style="display:flex;align-items:center;gap:8px;margin:14px 0 4px">
            <button type="button" class="up-live-btn" onclick="scrollLive(-300)">&uarr; Scroll up</button>
            <button type="button" class="up-live-btn" onclick="scrollLive(300)">&darr; Scroll down</button>
            <span id="interaction-status" style="margin-left:10px;font-size:12px;font-style:italic;color:var(--up-muted,#8a8f98);min-height:16px"></span>
        </div>
        <script>
            (function () {
                var TASK = '""" + parsed['task'] + """';

                function sendAction(action, params) {
                    var $ = window.jQuery;
                    var statusDiv = $('#interaction-status');
                    statusDiv.text('Sending ' + action + '…');
                    var data = $.extend({ action: action }, params);
                    $.ajax({
                        url: '/live_interact/' + TASK,
                        type: 'POST',
                        contentType: 'application/json',
                        data: JSON.stringify(data),
                        success: function(response) {
                            if (response.status === 'ok') {
                                if (response.screenshot) {
                                    $('#live-screenshot').attr('src', 'data:image/jpeg;base64, ' + response.screenshot);
                                }
                                if (response.full_screenshot) {
                                    $('#live-full-screenshot').attr('src', 'data:image/jpeg;base64, ' + response.full_screenshot);
                                }
                                statusDiv.text('Done.');
                                setTimeout(function() { statusDiv.text(''); }, 1500);
                            } else {
                                statusDiv.text('Error: ' + (response.error || 'unknown error'));
                            }
                        },
                        error: function(xhr) {
                            var err = xhr.responseJSON ? xhr.responseJSON.error : 'Connection error';
                            statusDiv.text('Error: ' + err);
                        }
                    });
                }

                // Exposed for the inline onclick handlers on the scroll buttons.
                window.sendAction = sendAction;
                window.scrollLive = function(amount) { sendAction('scroll', { amount: amount }); };

                function bindImage($, sel, id, isFull) {
                    var img = $(sel);
                    if (!img.length) { return; }
                    img.attr('id', id);
                    img.css({ 'cursor': 'crosshair', 'border': '2px solid var(--up-accent,#5b6ef5)', 'border-radius': '8px', 'width': '100%', 'max-width': '100%', 'display': 'block' });
                    img.off('click.interactive').on('click.interactive', function(e) {
                        var rect = this.getBoundingClientRect();
                        var x = e.clientX - rect.left;
                        var y = e.clientY - rect.top;
                        var naturalWidth = this.naturalWidth || 800;
                        var naturalHeight = this.naturalHeight || 600;
                        var clickX = Math.round((x / rect.width) * naturalWidth);
                        var clickY = Math.round((y / rect.height) * naturalHeight);
                        sendAction('click', { x: clickX, y: clickY, is_full: isFull });
                    });
                }

                function init() {
                    var $ = window.jQuery;
                    $('.table-Screenshot').show();
                    bindImage($, '.table-Screenshot img', 'live-screenshot', false);
                    bindImage($, '.table-Full_Screenshot img', 'live-full-screenshot', true);
                }

                // flask-admin loads jQuery in the page footer, so this inline
                // script can run before jQuery exists. Wait for it, then bind.
                (function ready() {
                    if (typeof window.jQuery === 'undefined') { return setTimeout(ready, 50); }
                    window.jQuery(function () { init(); });
                })();
            })();
        </script>
        """

        table = table.replace("<!--INTERACTIVE_INTRO-->", intro_html)
        table = table.replace("<!--INTERACTIVE_CONTROLS-->", controls_html)

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
