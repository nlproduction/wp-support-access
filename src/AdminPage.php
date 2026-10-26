<?php

namespace NLProduction\WordPress\SupportAccess;

/** Optional UI; embedders may use the service/REST API with their own UI. */
final class AdminPage
{
    private $access;

    public function __construct(SupportAccess $access)
    {
        $this->access = $access;
    }

    public function register(): void
    {
        add_action('admin_menu', function () {
            if ($this->access->canManage()) {
                add_options_page('Support access', 'Support access', 'manage_options', 'wp-support-access', [$this, 'render']);
            }
        });
    }

    public function render(): void
    {
        if (!$this->access->canManage()) {
            wp_die('You cannot manage support access.', 'Support access', ['response' => 403]);
        }
        nocache_headers();
        $config = [
            'url' => rest_url('wp-support-access/v1/grants'),
            'nonce' => wp_create_nonce('wp_rest'),
        ];
        ?>
        <div class="wrap" id="wpsa-root">
            <h1>Temporary support access</h1>
            <p>Create a link that signs your support team into this site's WordPress admin.
                Anyone with the link receives full administrator access until it expires or you revoke it.</p>
            <form id="wpsa-create">
                <table class="form-table" role="presentation">
                    <tr><th><label for="wpsa-label">Label</label></th>
                        <td><input id="wpsa-label" type="text" value="Support" maxlength="191" class="regular-text"></td></tr>
                    <tr><th><label for="wpsa-ttl">Expires in</label></th><td>
                        <select id="wpsa-ttl">
                            <option value="3600">1 hour</option>
                            <option value="86400" selected>24 hours</option>
                            <option value="604800">7 days</option>
                        </select>
                    </td></tr>
                </table>
                <p><button class="button button-primary" type="submit" id="wpsa-grant">Grant access &amp; create magic link</button></p>
            </form>
            <p id="wpsa-message" role="status" aria-live="polite"></p>
            <div id="wpsa-result" hidden>
                <p><label for="wpsa-link"><strong>Save this link now. It is shown only once.</strong></label></p>
                <input id="wpsa-link" type="text" readonly class="large-text code" autocomplete="off">
                <p><button id="wpsa-copy" class="button" type="button">Copy link</button></p>
            </div>
            <h2>Access grants</h2>
            <table class="widefat striped">
                <thead><tr><th>Label</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th>Action</th></tr></thead>
                <tbody id="wpsa-grants"></tbody>
            </table>
            <p><button id="wpsa-previous" class="button" type="button">Previous</button>
                <button id="wpsa-next" class="button" type="button">Next</button></p>
        </div>
        <script id="wpsa-config" type="application/json"><?php echo wp_json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?></script>
        <script>
        (() => {
            const config = JSON.parse(document.getElementById('wpsa-config').textContent);
            const el = id => document.getElementById('wpsa-' + id);
            let offset = 0;
            const pageSize = 20;
            const message = text => { el('message').textContent = text; };
            async function request(method, id = '', body) {
                // URL handles plain-permalink ?rest_route= URLs as well as /wp-json/.
                const url = new URL(config.url);
                if (id) {
                    if (url.searchParams.has('rest_route')) {
                        url.searchParams.set('rest_route', url.searchParams.get('rest_route').replace(/\/$/, '') + '/' + id);
                    } else {
                        url.pathname = url.pathname.replace(/\/$/, '') + '/' + id;
                    }
                }
                if (method === 'GET') {
                    url.searchParams.set('limit', String(pageSize));
                    url.searchParams.set('offset', String(offset));
                }
                const response = await fetch(url.href, {
                    method, credentials: 'same-origin', cache: 'no-store',
                    headers: {'Content-Type': 'application/json', 'X-WP-Nonce': config.nonce},
                    ...(body ? {body: JSON.stringify(body)} : {})
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.message || 'Request failed.');
                return data;
            }
            const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString() : '—';
            async function load() {
                const rows = await request('GET');
                el('grants').replaceChildren();
                rows.forEach(grant => {
                    const row = document.createElement('tr');
                    [grant.label, date(grant.created_at), date(grant.expires_at), date(grant.last_used_at),
                        grant.revoked_at ? 'Revoked' : grant.active ? 'Active' : 'Expired'].forEach(value => {
                        const cell = document.createElement('td');
                        cell.textContent = value;
                        row.appendChild(cell);
                    });
                    const actions = document.createElement('td');
                    if (grant.active || grant.user_id) {
                        const button = document.createElement('button');
                        button.type = 'button'; button.className = 'button'; button.textContent = 'Revoke';
                        button.addEventListener('click', async () => {
                            button.disabled = true;
                            try { await request('DELETE', grant.id); message('Access revoked. Existing support sessions ended.'); await load(); }
                            catch (error) { message(error.message); button.disabled = false; }
                        });
                        actions.appendChild(button);
                    }
                    row.appendChild(actions); el('grants').appendChild(row);
                });
                el('previous').disabled = offset === 0;
                el('next').disabled = rows.length < pageSize;
            }
            el('create').addEventListener('submit', async event => {
                event.preventDefault(); el('grant').disabled = true;
                el('result').hidden = true; el('link').value = '';
                try {
                    const grant = await request('POST', '', {label: el('label').value, ttl: Number(el('ttl').value)});
                    el('link').value = grant.url; el('result').hidden = false;
                    message('Access granted. Copy and share the link privately.');
                    offset = 0;
                    try { await load(); } catch (error) { message('Link created. Save it now. Could not refresh the list: ' + error.message); }
                } catch (error) { message(error.message); }
                finally { el('grant').disabled = false; }
            });
            el('copy').addEventListener('click', async () => {
                try { await navigator.clipboard.writeText(el('link').value); message('Link copied.'); }
                catch { el('link').focus(); el('link').select(); message('Copy the selected link.'); }
            });
            el('previous').addEventListener('click', () => { offset = Math.max(0, offset - pageSize); load().catch(error => message(error.message)); });
            el('next').addEventListener('click', () => { offset += pageSize; load().catch(error => message(error.message)); });
            // Do not retain the secret when restoring this page from browser history.
            window.addEventListener('pagehide', () => { el('link').value = ''; el('result').hidden = true; });
            load().catch(error => message(error.message));
        })();
        </script>
        <?php
    }
}
