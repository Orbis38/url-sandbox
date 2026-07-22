// Live task-queue polling. Rebuilds KPI counters and table rows every 2s.
(function () {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function cap(s) {
        s = String(s || '');
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    function actions(t) {
        var task = encodeURIComponent(t.task);
        var html = '';
        if (t.status === 'completed') {
            html += '<a class="up-link" href="/report/' + task + '" target="_blank">Report</a>' +
                    '<a class="up-link" href="/report/' + task + '/json" target="_blank">JSON</a>';
        }
        html += '<a class="up-link" href="/tasklog/' + task + '" target="_blank">Logs</a>';
        return html;
    }

    function renderRows(tasks) {
        if (!tasks || tasks.length === 0) {
            return '<tr><td colspan="6" class="text-center" style="color:var(--up-muted);padding:24px">' +
                'No tasks yet. Start a new analysis to populate the queue.</td></tr>';
        }
        var html = '';
        for (var i = 0; i < tasks.length; i++) {
            var t = tasks[i];
            html += '<tr>' +
                '<td class="up-target" title="' + esc(t.target) + '">' + esc(t.target) + '</td>' +
                '<td>' + esc(t.type) + '</td>' +
                '<td><span class="up-pill up-pill-' + esc(t.status) + '">' +
                    '<span class="up-pill-dot"></span>' + esc(cap(t.status)) + '</span></td>' +
                '<td>' + esc(t.submitted) + '</td>' +
                '<td>' + esc(t.duration) + '</td>' +
                '<td class="up-row-actions">' + actions(t) + '</td>' +
            '</tr>';
        }
        return html;
    }

    function poll() {
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
                    $("#kpi-total").text(data.kpis.total);
                    $("#kpi-running").text(data.kpis.running);
                    $("#kpi-queued").text(data.kpis.queued);
                    $("#kpi-completed").text(data.kpis.completed);
                }
                if (data && data.tasks) {
                    $("#queue-body").html(renderRows(data.tasks));
                }
            },
            complete: function () {
                setTimeout(poll, 2000);
            }
        });
    }

    $(document).ready(function () {
        setTimeout(poll, 2000);
    });
})();
