// Live task-queue polling. Rebuilds KPI counters and table rows every 2s.
(function () {
    var PROBLEMS = ['failed', 'timed_out', 'interrupted', 'cancelled'];
    var LABELS = {queued: 'Queued', running: 'Running', completed: 'Completed', failed: 'Failed',
                  timed_out: 'Timed out', interrupted: 'Interrupted', cancelled: 'Cancelled'};
    var filter = 'all';
    var query = '';

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function label(status) {
        status = String(status || '');
        return LABELS[status] || (status.charAt(0).toUpperCase() + status.slice(1)).replace(/_/g, ' ');
    }

    // One action per row: the report page carries logs and the JSON export.
    function actions(t) {
        var href = '/report/' + encodeURIComponent(t.task);
        if (['completed', 'failed', 'timed_out', 'interrupted'].indexOf(t.status) !== -1) {
            return '<a class="up-link up-link-primary" href="' + href + '" target="_blank">Report</a>';
        }
        return '<a class="up-link" href="' + href + '" target="_blank">' +
            (t.status === 'cancelled' ? 'Details' : 'Progress') + '</a>';
    }

    function renderRows(tasks) {
        if (!tasks || tasks.length === 0) {
            return '<tr><td colspan="6" class="up-empty">' +
                'No tasks yet. Start a new analysis to populate the queue.</td></tr>';
        }
        var html = '';
        for (var i = 0; i < tasks.length; i++) {
            var t = tasks[i];
            html += '<tr data-status="' + esc(t.status) + '">' +
                '<td class="up-target"><div class="up-target-url" title="' + esc(t.target) + '">' +
                    '<span class="up-target-host">' + esc(t.host || t.target) + '</span>' +
                    '<span class="up-target-rest">' + esc(t.rest) + '</span></div>' +
                    '<div class="up-target-id">' + esc(t.short || String(t.task || '').slice(0, 8)) + '</div></td>' +
                '<td style="color: var(--up-text-mid)">' + esc(t.type) + '</td>' +
                '<td><span class="up-pill up-pill-' + esc(t.status) + '">' +
                    '<span class="up-pill-dot"></span>' + esc(t.status_label || label(t.status)) + '</span></td>' +
                '<td class="up-data">' + esc(t.submitted) + '</td>' +
                '<td class="up-data up-num" style="color: var(--up-text)">' + esc(t.duration) + '</td>' +
                '<td class="up-row-actions">' + actions(t) + '</td>' +
            '</tr>';
        }
        return html;
    }

    function matches(row) {
        var status = row.getAttribute('data-status');
        if (filter === 'problems' && PROBLEMS.indexOf(status) === -1) return false;
        if (filter !== 'all' && filter !== 'problems' && status !== filter) return false;
        return !query || row.textContent.toLowerCase().indexOf(query) !== -1;
    }

    // Filtering is client side over the rows already on the page.
    function applyFilter() {
        var body = document.getElementById('queue-body');
        if (!body) return;
        var rows = body.querySelectorAll('tr[data-status]');
        var shown = 0;
        for (var i = 0; i < rows.length; i++) {
            var ok = matches(rows[i]);
            rows[i].hidden = !ok;
            if (ok) shown++;
        }
        var empty = document.getElementById('queue-nomatch');
        if (rows.length && !shown) {
            if (!empty) {
                empty = document.createElement('tr');
                empty.id = 'queue-nomatch';
                empty.innerHTML = '<td colspan="6" class="up-empty">No tasks match this filter.</td>';
                body.appendChild(empty);
            }
        } else if (empty) {
            empty.parentNode.removeChild(empty);
        }
    }

    function bindControls() {
        var group = document.getElementById('queue-filter');
        if (group) {
            group.addEventListener('click', function (event) {
                var button = event.target.closest('button[data-filter]');
                if (!button) return;
                filter = button.getAttribute('data-filter');
                var buttons = group.querySelectorAll('button');
                for (var i = 0; i < buttons.length; i++) {
                    buttons[i].setAttribute('aria-pressed', buttons[i] === button ? 'true' : 'false');
                }
                applyFilter();
            });
        }
        var search = document.getElementById('queue-search');
        if (search) {
            search.addEventListener('input', function () {
                query = search.value.trim().toLowerCase();
                applyFilter();
            });
        }
    }

    function poll() {
        if (document.hidden) {
            setTimeout(poll, 5000);
            return;
        }
        var delay = 5000;
        $.ajaxSetup({ headers: { "X-CSRFToken": csrf_token } });
        $.ajax({
            type: "POST",
            url: "/queue/",
            data: JSON.stringify({}),
            contentType: "application/json; charset=utf-8",
            dataType: "json",
            timeout: 8000,
            success: function (data) {
                if (data && data.kpis) {
                    delay = (data.kpis.running || data.kpis.queued) ? 2000 : 5000;
                    $("#kpi-total").text(data.kpis.total);
                    $("#kpi-running").text(data.kpis.running);
                    $("#kpi-queued").text(data.kpis.queued);
                    $("#kpi-completed").text(data.kpis.completed);
                    $("#kpi-failed").text(data.kpis.failed || 0);
                }
                if (data && data.tasks) {
                    $("#queue-body").html(renderRows(data.tasks));
                    applyFilter();
                }
            },
            complete: function () {
                setTimeout(poll, delay);
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindControls);
    } else {
        bindControls();
    }

    $(document).ready(function () {
        setTimeout(poll, 2000);
    });
})();
