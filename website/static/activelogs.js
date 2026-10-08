(function () {
    var cursor = 0;
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
                var box = $('.activelogs');
                if (data.reset || data.logs) {
                    var text = data.reset ? data.logs : box.val() + '\n' + data.logs;
                    box.val(text.split('\n').slice(-2000).join('\n'));
                    box.scrollTop(box[0].scrollHeight - box.height());
                }
                cursor = data.id;
                delay = data.has_more ? 100 : (data.logs ? 1000 : 3000);
            },
            complete: function () { setTimeout(poll, delay); }
        });
    }
    $(document).ready(poll);
})();
