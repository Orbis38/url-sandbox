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

    function init() {
        distribute();
        bindTabs();
        bindCopy();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
