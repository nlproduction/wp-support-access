# WP Support Access

Grant temporary access to WordPress in one click. Share a magic link with your
support team; clicking it opens wp-admin without entering a username or password.
Revoke the grant to end the associated WordPress sessions immediately.

A dependency-free PHP package for embedding in your own WordPress plugin.
The main class is `SupportAccess`. Adapted from MapSVG's support-token and
magic-login functionality; it runs independently of MapSVG.

Requires WordPress 5.9+, PHP 7.4+ and the usual WordPress MySQL database.

## Embed in your own plugin

Until the package is registered on Packagist, add its GitHub VCS repository to
your project's `composer.json`:

```json
{
  "repositories": [
    {"type": "vcs", "url": "https://github.com/nlproduction/wp-support-access"}
  ],
  "require": {"nlproduction/wp-support-access": "^1.0"}
}
```

Then run `composer install`. In your plugin's main file:

```php
require_once __DIR__ . '/vendor/autoload.php';

use NLProduction\WordPress\SupportAccess\SupportAccess;

$support = new SupportAccess();
$support->register();

register_activation_hook(__FILE__, [$support, 'initialize']);
register_deactivation_hook(__FILE__, [$support, 'deactivate']);
```

Register the service on **every request**, including public requests. This
registers token storage initialization, the REST API, magic-login handling and
session-expiry checks. Do not put registration inside `is_admin()`.

For a network-activated host plugin, call `deactivate()` for every site on network
deactivation, using `switch_to_blog()` / `restore_current_blog()`.

Storage initializes on `init` for each site. Call the API after `init`, or call
`install()` explicitly from an activation/migration hook. If your host plugin can
be uninstalled without deactivation, its uninstall hook must also revoke grants.

## Get the magic link in PHP

Call `issue()` from your plugin's nonce-protected administrator action. It
creates the temporary support account and returns the **complete magic link in
`$grant['url']`**. You do not need to assemble the URL or write a login handler.

```php
$grant = $support->issue([
    'label' => 'Support ticket #123',
    'ttl' => 3600, // seconds; integer from 60 through 604800
]);

if (is_wp_error($grant)) {
    // Show/return the error in your plugin's admin UI.
    $errorMessage = $grant->get_error_message();
    return;
}

$magicLink = $grant['url']; // Share this URL with your support team.
$grantId = $grant['id'];   // Keep this ID to revoke access later.

// For example, display the link in your existing plugin's admin page:
echo '<input type="text" readonly value="' . esc_attr($magicLink) . '">';
```

The result looks like
`https://example.com/wp-login.php?action=wpsa_login&wpsa_token=…`.
Opening it signs the support user into WordPress and redirects to wp-admin.

**The raw URL is returned only when the grant is created.** Only a token hash is
stored, so `grants()` cannot return the original link later. Display or return it
to the administrator immediately. If it is lost, revoke the grant and issue a
new one. Each call to `issue()` creates a new grant; do not call it automatically
when your plugin bootstraps or its settings page loads.

The default lifetime is **24 hours**. You can set an integer `ttl` between 60 and
604800 seconds. The link is reusable until expiration or revocation.

## Add a one-click button to your plugin

The registered REST API already creates and returns magic links. Put this in
your **existing plugin's admin-page renderer**. The button sends one authenticated
request and displays the returned URL:

```php
<?php
if (!$support->canManage()) {
    return;
}
$supportRequest = [
    'url' => rest_url('wp-support-access/v1/grants'),
    'nonce' => wp_create_nonce('wp_rest'),
];
?>
<button type="button" id="my-plugin-support-create">Create magic link</button>
<input type="text" id="my-plugin-support-link" readonly hidden>
<p id="my-plugin-support-status" role="status"></p>
<script>
(() => {
    const config = <?php echo wp_json_encode($supportRequest, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
    const button = document.getElementById('my-plugin-support-create');
    const link = document.getElementById('my-plugin-support-link');
    const status = document.getElementById('my-plugin-support-status');

    button.addEventListener('click', async () => {
        button.disabled = true;
        link.value = ''; link.hidden = true;
        status.textContent = 'Creating access…';
        try {
            const response = await fetch(config.url, {
                method: 'POST', credentials: 'same-origin', cache: 'no-store',
                headers: {'Content-Type': 'application/json', 'X-WP-Nonce': config.nonce},
                body: JSON.stringify({label: 'Support', ttl: 86400})
            });
            const grant = await response.json();
            if (!response.ok) throw new Error(grant.message || 'Could not create access.');

            link.value = grant.url; // This is the complete magic link.
            link.hidden = false;
            link.focus(); link.select();
            status.textContent = 'Copy and save this link now. It is shown only once.';
            // grant.id can be passed to DELETE /grants/{id} to revoke access.
        } catch (error) {
            status.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
    window.addEventListener('pagehide', () => { link.value = ''; link.hidden = true; });
})();
</script>
```

The service checks administrator permissions on the server; WordPress verifies
the cookie authentication and nonce. The URL from `rest_url()` also supports
plain permalink installations. Register the service before rendering this page.

## Other PHP operations

These calls run inside a loaded WordPress installation. Management calls require
the current user to have `manage_options`; temporary support accounts cannot
create, list or revoke grants through this package.

```php
$support->grants(20, 0);       // Safe metadata, with limit and offset.
$support->validate($token);    // Safe metadata or WP_Error; no login side effect.
$support->revoke($grantId);    // true or WP_Error; ends associated sessions.
```

`login($token)` validates the token, creates a WordPress session and sets its auth
cookies; it must run before output. `register()` handles this automatically at
`wp-login.php?action=wpsa_login&wpsa_token=…`, then redirects to the site's wp-admin.
The route does not need permalink rules or a rewrite flush. `wpsa_token` avoids
WordPress's reserved `key` password-reset parameter.

Embedding callers must protect their own HTTP actions with WordPress capability
checks and nonces. The provided REST routes already use WordPress authentication
and permissions, including cookie nonce validation.

## REST API

Namespace: `wp-support-access/v1`.

- `GET /grants?limit=20&offset=0` — list metadata. Limit is clamped to 1–100.
- `POST /grants` — create a grant: `{"label":"Ticket #123","ttl":86400}`.
- `DELETE /grants/{id}` — revoke a grant. Repeated revocation is safe.

Creation returns HTTP 201 with the metadata plus `token` and `url`. List responses
never include raw tokens, their hashes or reconstructable URLs. Successful
responses include `Cache-Control: no-store, private`.

Cookie-authenticated callers must send a valid `X-WP-Nonce` for `wp_rest`.
WordPress application-password authentication is also subject to the management
capability check. Use `rest_url()` to generate the base URL: plain permalink
installations use `?rest_route=…` instead of `/wp-json/…`.

## Lifecycle and storage

- `{$wpdb->prefix}wpsa_grants` stores SHA-256 hashes of random 256-bit tokens,
  grant IDs, labels, account/issuer IDs and UTC Unix timestamps.
- Every grant creates a distinct `wpsa_…` user with a random password unrelated
  to the token. Existing usernames/emails are never adopted or overwritten.
- A `_wpsa_grant` user-meta marker binds the user to the grant and site.
  Both directions of this ownership are checked before login or account cleanup.
- Expiration is enforced on every authenticated request, independently of
  WP-Cron. Both cookies and the WordPress session store are bounded by expiry.
- Revocation records the grant's revoked state before account cleanup. Active
  sessions are destroyed. On a single site, the owned temporary user is deleted
  and its content reassigned to the administrator who issued the grant.
- If that administrator no longer exists, cleanup strips the support account's
  role and retains it to avoid deleting authored content. Revocation reports a
  cleanup error; expiry/revocation still blocks its access. Restore the issuer or
  reassign content manually before retrying cleanup.
- Hourly WP-Cron retires expired accounts in batches of 100. Audit rows remain;
  raw links cannot be recovered from them. Revocation/expiry can return cleanup
  errors for inconsistent ownership rather than touching an unrelated account.
- Deactivation revokes all grants and cleans up accounts/sessions. The table
  remains for audit. Deactivate before manually removing files.

### Multisite

Tables, grants and cleanup are site-scoped. A support account belongs to one
site; it is not granted super-admin privileges, and authentication is rejected
on other sites. Cleanup removes only that site's membership and reassigns that
site's content through `wp_delete_user()`. It never calls `wpmu_delete_user()` or
deletes a network account globally. A revoked account's network identity and
ownership marker remain, without membership on the granting site.

### Trust boundary

Use HTTPS and share links privately. A bearer link grants **full site
administrator privileges**; it is not a sandbox. An administrator can install
code, disable plugins or create other accounts. Expiration and revocation govern
this package's credentials and sessions; they cannot undo actions performed by
an administrator or contain intentionally hostile administrator-level code.
Standard web servers, proxies and mail scanners may see or follow URL tokens;
keep query strings out of analytics/access logs where possible. The login
response uses `no-store` and `Referrer-Policy: no-referrer` and immediately
redirects to a token-free admin URL.

The package includes the WordPress access lifecycle. MapSVG-specific diagnostic
log viewers, database browsers, Clockwork, license/AI credentials and MapSVG UI
are separate integrations and are not bundled. Existing MapSVG links and its
legacy token table are not automatically migrated or replaced.

## Verification

```sh
WPSA_WP_CORE=/path/to/wordpress python3 tests/integration.py
```

Requires `php` with mysqli, `mysqld` and `mysql` (MySQL 8+), and Python 3.9+.
The runner copies WordPress core, creates a fresh database in its own socket-only
MySQL process, installs and activates the actual plugin, and starts a loopback
PHP server. It never loads the source site's `wp-config.php`. HTTP tests use
real WordPress login forms, cookies, REST nonce verification and wp-admin.
External WordPress HTTP calls and mail are blocked. Services and data are
removed on success or failure.

Checks include issuance/validation/revocation, editor/guest/support permissions,
invalid input, hash-only storage, account ownership, expiry before cron, content
reassignment, storage failure, cookie expiry, authenticated REST management,
forged links and actual plugin deactivation. Browser UI automation, production
hosting caches and third-party security plugins require separate verification.

The same runner also creates a real two-site network and checks site-scoped
tokens/sessions, support-user privileges, membership and content cleanup, and
network-wide plugin deactivation.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
