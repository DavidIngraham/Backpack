(function () {
    const panel = document.getElementById('tls_panel');
    if (!panel) return;
    const message = document.getElementById('tls_message');
    const upload = document.getElementById('tls_upload');
    const remove = document.getElementById('tls_remove');
    const restart = document.getElementById('tls_restart');
    let busy = false;
    async function refresh() {
        const response = await fetch('/tls/status', {cache: 'no-store'});
        if (!response.ok) throw new Error('Unable to read TLS status.');
        const state = await response.json();
        document.getElementById('tls_status').textContent = state.restart_needed
            ? 'Saved changes are waiting for a restart.'
            : state.configured ? (state.running ? 'WSS ready: ' : 'WSS unavailable: ') + state.hostname +
                '. Certificate expires ' + state.expires + '. Allowed PWA: ' + state.origin + '.'
            : 'No TLS certificate installed.';
        document.getElementById('tls_fingerprint').textContent = state.fingerprint ? 'Certificate SHA-256: ' + state.fingerprint : '';
        upload.disabled = busy || !state.can_provision;
        remove.disabled = busy || !state.can_provision || !state.configured;
        restart.disabled = busy || !state.restart_needed;
        if (state.error) message.textContent = state.error;
    }
    async function change(method, path, body) {
        if (busy) return;
        busy = true; upload.disabled = remove.disabled = restart.disabled = true;
        message.textContent = 'Working...';
        try {
            const response = await fetch(path, {method: method, body: body});
            const result = await response.text();
            if (!response.ok) throw new Error(result);
            message.textContent = result;
        } catch (error) { message.textContent = error.message; }
        finally {
            busy = false;
            if (path !== '/tls/restart') refresh().catch(function (error) { message.textContent = error.message; });
        }
    }
    document.getElementById('tls_form').addEventListener('submit', function (event) {
        event.preventDefault();
        const file = document.getElementById('tls_file').files[0];
        if (!file) return;
        if (file.size > 8192) { message.textContent = 'TLS bundle exceeds 8192 bytes.'; return; }
        const body = new FormData(); body.append('credentials', file);
        change('POST', '/tls/credentials', body);
    });
    remove.addEventListener('click', function () { change('DELETE', '/tls/credentials'); });
    restart.addEventListener('click', function () { change('POST', '/tls/restart'); });
    fetch('/config').then(function (response) { return response.json(); }).then(function (data) {
        if (data.config && data.config.tls) { panel.hidden = false; return refresh(); }
    }).catch(function (error) { message.textContent = error.message; });
})();
