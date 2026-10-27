// Email report: size the inert message iframe, and turn its links into an inspector
// (real destination, flags, open in the URL sandbox) instead of navigation.
(function () {
    var links = [];
    var flagInfo = {labels: {}, risky: []};
    var current = null;

    function readJson(id, fallback) {
        var node = document.getElementById(id);
        if (!node) return fallback;
        try { return JSON.parse(node.textContent); } catch (e) { return fallback; }
    }

    function isWeb(url) {
        return /^https?:\/\//i.test(url || '');
    }

    // Open a link in the URL sandbox: a normal New Analysis submission in a new tab,
    // remembered on this report through parent_task.
    function analyze(link, live) {
        var form = document.getElementById('sandbox-form');
        if (!form || !link || !isWeb(link.target)) return;
        form.elements.buffer.value = link.target;
        var interactive = form.querySelector('input[name="choices"][value="interactive"]');
        if (interactive) interactive.disabled = !live;
        form.submit();
    }

    function copy(text, button) {
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
            if (!button) return;
            var label = button.textContent;
            button.textContent = 'Copied';
            setTimeout(function () { button.textContent = label; }, 1200);
        });
    }

    // ── popover ────────────────────────────────────────────
    var pop = document.getElementById('link-pop');

    function field(name) {
        return pop.querySelector('[data-pop="' + name + '"]');
    }

    function closePop() {
        if (pop) pop.hidden = true;
        current = null;
    }

    function openPop(link, x, y) {
        if (!pop || !link) return;
        current = link;
        field('display').textContent = link.display || '—';
        field('target').textContent = link.target;
        field('url').textContent = link.url;
        var wrapped = link.url !== link.target;
        pop.querySelectorAll('[data-pop-wrapped]').forEach(function (node) { node.hidden = !wrapped; });
        var flags = field('flags');
        flags.textContent = '';
        (link.flags || []).forEach(function (flag) {
            var chip = document.createElement('span');
            chip.className = 'up-flag' + (flagInfo.risky.indexOf(flag) !== -1 ? ' is-bad' : '');
            chip.textContent = flagInfo.labels[flag] || flag;
            flags.appendChild(chip);
        });
        var web = isWeb(link.target);
        pop.querySelectorAll('[data-pop-analyze]').forEach(function (node) { node.disabled = !web; });
        pop.querySelector('[data-pop-noweb]').hidden = web;
        pop.hidden = false;
        // keep it inside the viewport, below-right of the click when there is room
        var width = pop.offsetWidth, height = pop.offsetHeight;
        var left = Math.min(Math.max(8, x - 24), window.innerWidth - width - 8);
        var top = y + 14;
        if (top + height > window.innerHeight - 8) top = Math.max(8, y - height - 14);
        pop.style.left = left + 'px';
        pop.style.top = top + 'px';
        pop.querySelector('[data-pop-analyze]').focus({preventScroll: true});
    }

    function bindPop() {
        if (!pop) return;
        pop.addEventListener('click', function (event) {
            var target = event.target.closest('button');
            if (!target || !current) return;
            if (target.hasAttribute('data-pop-close')) closePop();
            else if (target.hasAttribute('data-pop-copy')) copy(current.target, target);
            else if (target.hasAttribute('data-pop-analyze')) {
                analyze(current, target.hasAttribute('data-live'));
                closePop();
            }
        });
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') closePop();
        });
        document.addEventListener('mousedown', function (event) {
            if (!pop.hidden && !pop.contains(event.target)) closePop();
        });
        // the popover is fixed to the viewport: drop it when the page scrolls under it
        document.addEventListener('scroll', closePop, true);
        window.addEventListener('resize', closePop);
    }

    // ── inert iframes (message body, rendered HTML attachments) ──
    function bindFrame(frame) {
        function fit() {
            var doc = frame.contentDocument;
            if (!doc || !doc.documentElement) return;
            var height = Math.max(doc.documentElement.scrollHeight, doc.body ? doc.body.scrollHeight : 0);
            frame.style.height = Math.max(160, Math.min(height + 4, 20000)) + 'px';
        }

        function wire() {
            var doc = frame.contentDocument;
            if (!doc || doc.location.href === 'about:blank') return;
            fit();
            // images (inline cid: ones) can change the height after load
            Array.prototype.forEach.call(doc.images || [], function (image) {
                if (!image.complete) image.addEventListener('load', fit);
            });
            doc.addEventListener('click', function (event) {
                var anchor = event.target.closest && event.target.closest('a, area');
                if (!anchor) return;
                event.preventDefault();
                var id = anchor.getAttribute('data-up-link');
                if (id === null) return;
                var rect = frame.getBoundingClientRect();
                openPop(links[parseInt(id, 10)], rect.left + event.clientX, rect.top + event.clientY);
            });
            // no form in the message may submit (the sandbox attribute blocks it too)
            doc.addEventListener('submit', function (event) { event.preventDefault(); }, true);
            doc.addEventListener('mousedown', function () { if (pop && !pop.hidden) closePop(); });
        }

        frame.addEventListener('load', wire);
        if (frame.contentDocument && frame.contentDocument.readyState === 'complete') wire();
        window.addEventListener('resize', fit);
        return fit;
    }

    function bindFrames() {
        var frame = document.getElementById('mail-frame');
        if (frame) {
            var fit = bindFrame(frame);
            // a hidden tab has no layout: measure again when the Message tab is shown
            var tab = document.getElementById('tab-message');
            if (tab) tab.addEventListener('click', function () { setTimeout(fit, 0); });
        }
        Array.prototype.forEach.call(document.querySelectorAll('.up-inert-frame'), bindFrame);
    }

    // "View rendered" on an HTML attachment: load its inert rendering on first use only
    function toggleRendered(button) {
        var box = document.querySelector('[data-render-box="' + button.getAttribute('data-render') + '"]');
        if (!box) return;
        var frame = box.querySelector('iframe');
        if (frame && !frame.getAttribute('src')) frame.setAttribute('src', frame.getAttribute('data-src'));
        box.hidden = !box.hidden;
        button.textContent = box.hidden ? 'View rendered' : 'Hide rendering';
    }

    function bindPage() {
        document.addEventListener('click', function (event) {
            var button = event.target.closest('[data-analyze]');
            if (button) {
                analyze(links[parseInt(button.getAttribute('data-analyze'), 10)], button.hasAttribute('data-live'));
                return;
            }
            var render = event.target.closest('[data-render]');
            if (render) {
                toggleRendered(render);
                return;
            }
            var jump = event.target.closest('[data-goto-tab]');
            if (jump) {
                var tab = document.getElementById(jump.getAttribute('data-goto-tab'));
                if (tab) { tab.click(); tab.focus(); }
            }
        });
    }

    function init() {
        links = readJson('email-links', []);
        flagInfo = readJson('email-link-flags', flagInfo);
        bindPop();
        bindFrames();
        bindPage();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
