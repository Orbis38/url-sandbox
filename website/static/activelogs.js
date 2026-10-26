(function () {
    var cursor = 0;
    var buffer = '';
    var paused = false;

    function show() {
        var box = $('.activelogs');
        box.val(buffer);
        box.scrollTop(box[0].scrollHeight - box.height());
        var count = document.getElementById('log-count');
        if (count) {
            var lines = buffer ? buffer.split('\n').length : 0;
            count.textContent = lines + (lines === 1 ? ' line' : ' lines');
        }
    }

    function poll() {
        if (document.hidden) {
            setTimeout(poll, 5000);
            return;
        }
        var delay = 2000;
        $.ajax({
            type: 'POST', url: '/activelogs/',
            headers: { 'X-CSRFToken': csrf_token },
            data: JSON.stringify({ id: cursor }),
            contentType: 'application/json; charset=utf-8', dataType: 'json', timeout: 8000,
            success: function (data) {
                if (data.reset || data.logs) {
                    var text = data.reset ? data.logs : buffer + '\n' + data.logs;
                    buffer = text.split('\n').slice(-2000).join('\n');
                    if (!paused) show();
                }
                cursor = data.id;
                delay = data.has_more ? 100 : (data.logs ? 1000 : 3000);
            },
            complete: function () { setTimeout(poll, delay); }
        });
    }

    function bindControls() {
        var pause = document.getElementById('log-pause');
        if (pause) {
            pause.addEventListener('click', function () {
                paused = !paused;
                pause.setAttribute('aria-pressed', paused ? 'true' : 'false');
                pause.querySelector('span').textContent = paused ? 'Resume' : 'Pause';
                var status = document.getElementById('log-status');
                status.classList.toggle('is-paused', paused);
                document.getElementById('log-status-text').textContent = paused ? 'Paused' : 'Streaming';
                if (!paused) show();
            });
        }
        var copy = document.getElementById('log-copy');
        if (copy) {
            copy.addEventListener('click', function () {
                if (navigator.clipboard) navigator.clipboard.writeText(document.getElementById('log').value);
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindControls);
    } else {
        bindControls();
    }
    $(document).ready(poll);
})();
