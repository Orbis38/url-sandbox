// Report page: sort the sections qbreport renders into tabs, and wire the tabs.
(function () {
    // section header (as written by backend/qbreport.py) -> tab, and whether it starts open
    var SECTIONS = {
        'Screenshot': ['overview', true],
        'Security & Phishing Heuristics': ['overview', true],
        'DNS Records': ['network', true],
        'Response Headers': ['network', true],
        'Request Headers': ['network', false],
        'Certificate': ['network', true],
        'Sniffer': ['network', false],
        'Extracted links': ['content', true],
        'Extracted scripts': ['content', false],
        'OCR Words': ['content', false],
        'Full Screenshot': ['media', true],
        'Network Graph': ['media', true],
        'Logs': ['logs', true],
        'Browser': ['logs', false]
    };
    var EMPTY = {
        overview: 'No screenshot or page data was captured. The Logs tab shows what happened.',
        network: 'No DNS, header, certificate or packet data was recorded.',
        content: 'No links, scripts or page text were extracted.',
        media: 'No full-page screenshot or network graph was captured for this run.',
        logs: 'No log lines were recorded for this task.'
    };

    function sectionName(node) {
        var th = node.querySelector('thead th');
        return th ? th.textContent.trim() : '';
    }

    // Reports stored before qbreport kept non-ASCII text show it as "\u2014" style escapes.
    // Re-decode string literals of JSON blocks only; numbers and layout stay untouched.
    function unescapeJson(node) {
        var blocks = node.querySelectorAll('pre');
        for (var i = 0; i < blocks.length; i++) {
            var text = blocks[i].textContent;
            if (text.indexOf('\\u') === -1) continue;
            try { JSON.parse(text); } catch (e) { continue; }
            blocks[i].textContent = text.replace(/"(?:[^"\\]|\\.)*"/g, function (literal) {
                return JSON.stringify(JSON.parse(literal));
            });
        }
    }

    function setOpen(node, open) {
        var body = node.querySelector('tbody');
        if (body) body.style.display = open ? '' : 'none';
        node.classList.toggle('is-open', open);
    }

    function distribute() {
        var source = document.getElementById('report-source');
        if (!source) return;
        var counts = {overview: 0, network: 0, content: 0, media: 0, logs: 0};
        var nodes = Array.prototype.slice.call(source.childNodes);
        var hasReport = !source.querySelector('.up-empty-box');
        nodes.forEach(function (node) {
            if (node.nodeType !== 1) return;
            var tab = 'overview';
            if (node.classList.contains('tablewrapper')) {
                var name = sectionName(node);
                var rule = SECTIONS[name] || ['overview', true];
                tab = rule[0];
                setOpen(node, rule[1]);
                unescapeJson(node);
                if (name === 'Logs') node.classList.add('up-log-section');
                counts[tab]++;
            } else if (node.tagName !== 'SCRIPT' && node.tagName !== 'STYLE') {
                counts[tab]++;
            }
            document.getElementById('panel-' + tab).appendChild(node);
        });
        Object.keys(counts).forEach(function (tab) {
            var count = document.querySelector('#tab-' + tab + ' .up-tab-count');
            if (count && tab !== 'overview' && counts[tab]) count.textContent = counts[tab];
            if (!counts[tab] && hasReport) {
                var empty = document.createElement('div');
                empty.className = 'up-empty-box';
                empty.innerHTML = '<strong>Nothing here</strong><span></span>';
                empty.querySelector('span').textContent = EMPTY[tab];
                document.getElementById('panel-' + tab).appendChild(empty);
            }
        });
        source.parentNode.removeChild(source);
    }

    function select(tab) {
        var tabs = document.querySelectorAll('#report-tabs [role="tab"]');
        for (var i = 0; i < tabs.length; i++) {
            var on = tabs[i] === tab;
            tabs[i].setAttribute('aria-selected', on ? 'true' : 'false');
            tabs[i].tabIndex = on ? 0 : -1;
            document.getElementById(tabs[i].getAttribute('aria-controls')).hidden = !on;
        }
    }

    function bindTabs() {
        var list = document.getElementById('report-tabs');
        if (!list) return;
        list.addEventListener('click', function (event) {
            var tab = event.target.closest('[role="tab"]');
            if (tab) select(tab);
        });
        list.addEventListener('keydown', function (event) {
            if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
            var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
            var index = tabs.indexOf(document.activeElement);
            if (index === -1) return;
            var next = tabs[(index + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
            select(next);
            next.focus();
            event.preventDefault();
        });
    }

    function bindCopy() {
        document.addEventListener('click', function (event) {
            var button = event.target.closest('[data-copy]');
            if (!button || !navigator.clipboard) return;
            navigator.clipboard.writeText(button.getAttribute('data-copy')).then(function () {
                button.setAttribute('title', 'Copied');
            });
        });
    }

    // same format as _format_duration in web.py
    function formatDuration(secs) {
        secs = Math.max(0, Math.floor(secs));
        if (secs < 60) return secs + 's';
        var rest = secs % 60;
        return Math.floor(secs / 60) + 'm ' + (rest < 10 ? '0' : '') + rest + 's';
    }

    // Count the elapsed time up from the server's figure (no client clock involved).
    function tickElapsed() {
        var elapsed = document.getElementById('run-elapsed');
        if (!elapsed) return;
        var base = parseInt(elapsed.getAttribute('data-seconds'), 10) || 0;
        var loaded = Date.now();
        setInterval(function () {
            elapsed.textContent = formatDuration(base + (Date.now() - loaded) / 1000);
        }, 1000);
    }

    function showRunning() {
        var pill = document.getElementById('run-status');
        if (pill && pill.classList.contains('up-pill-queued')) {
            pill.classList.replace('up-pill-queued', 'up-pill-running');
            pill.lastElementChild.textContent = 'Running';
        }
        var title = document.getElementById('run-wait-title');
        if (title) title.textContent = 'Analyzing in the sandbox\u2026';
    }

    // While the task is still queued or running, reload once it reaches a final state.
    function watchProgress() {
        var split = document.querySelector('.up-report-split');
        if (!split || ['queued', 'running'].indexOf(split.getAttribute('data-status')) === -1) return;
        tickElapsed();
        var url = '/api/v1/tasks/' + encodeURIComponent(split.getAttribute('data-task'));
        var timer = null;
        var inFlight = false;
        function schedule(delay) {
            clearTimeout(timer);
            timer = setTimeout(check, delay);
        }
        function check() {
            if (document.hidden) return schedule(5000);
            if (inFlight) return;
            inFlight = true;
            // A request that hangs (e.g. on a stale keep-alive connection) must not stall
            // the polling chain, so each one is abandoned after 5s; never reuse a cached answer.
            var controller = window.AbortController ? new AbortController() : null;
            var abort = controller ? setTimeout(function () { controller.abort(); }, 5000) : null;
            fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' },
                         signal: controller ? controller.signal : undefined })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (data) {
                    if (data && ['queued', 'running'].indexOf(data.status) === -1) {
                        window.location.reload();
                        return;
                    }
                    if (data && data.status === 'running') showRunning();
                    schedule(2000);
                })
                .catch(function () { schedule(1000); })
                .then(function () { clearTimeout(abort); inFlight = false; });
        }
        // coming back to the tab checks at once instead of waiting for the next tick
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) schedule(0);
        });
        schedule(2000);
    }

    function init() {
        distribute();
        bindTabs();
        bindCopy();
        watchProgress();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
