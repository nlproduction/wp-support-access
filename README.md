# WP Support Access

Grant temporary access to WordPress in one click. Share a magic link with your
support team; clicking it opens wp-admin without entering a username or password.
Revoke the grant to end the associated WordPress sessions immediately.

A dependency-free PHP package with one main class, `SupportAccess`, and an
optional ready-to-install WordPress plugin. Adapted from MapSVG's support-token
and magic-login functionality; it runs independently of MapSVG.

## Install as a WordPress plugin

1. Download `wp-support-access.zip` from [Releases](https://github.com/nlproduction/wp-support-access/releases).
2. In WordPress, open **Plugins → Add New → Upload Plugin**, upload the ZIP and activate it.
3. Open **Settings → Support access** and click **Grant access & create magic link**.
4. Copy the link and share it privately with your support team.

The default lifetime is **24 hours**; the UI also offers one hour or seven days.
Each grant has its own account. Links can be used repeatedly until they expire or
are revoked, as needed for ongoing support. The original link is displayed only
when created. The list shows creation, expiration and last-use timestamps and a
**Revoke** button.

Requires WordPress 5.9+, PHP 7.4+ and the usual WordPress MySQL database.
No Composer installation or frontend build is needed for the plugin ZIP.

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
use NLProduction\WordPress\SupportAccess\AdminPage;

$support = new SupportAccess();
$support->register();

// Optional: omit this when supplying your own UI.
(new AdminPage($support))->register();

register_activation_hook(__FILE__, [$support, 'initialize']);
register_deactivation_hook(__FILE__, [$support, 'deactivate']);
```

For a network-activated host plugin, call `deactivate()` for every site on network
deactivation, using `switch_to_blog()` / `restore_current_blog()`. The standalone
plugin entry point already implements this in batches. Do not activate the
standalone plugin alongside an embedded copy; register one owner of the service.

Storage initializes on `init` for each site. Call the API after `init`, or call
`install()` explicitly from an activation/migration hook. If your host plugin can
be uninstalled without deactivation, its uninstall hook must also revoke grants.

## PHP API

The following calls run inside a loaded WordPress installation. Management calls
require the current user to have `manage_options`; temporary support accounts
cannot create, list or revoke grants through this package.

```php
$grant = $support->issue([
    'label' => 'Support ticket #123',
    'ttl' => 3600, // seconds; integer from 60 through 604800
]);

if (is_wp_error($grant)) {
    // Handle the error; do not log secrets from successful responses.
    return;
}

$grant['id'];      // Stable grant ID for revocation.
$grant['url'];     // Full magic link, returned only at creation.
$grant['token'];   // Raw bearer token, returned only at creation.

$support->grants(20, 0);       // Safe metadata, with limit and offset.
$support->validate($token);    // Safe metadata or WP_Error; no login side effect.
$support->revoke($grant['id']); // true or WP_Error; ends associated sessions.
```

`login($token)` validates the token, creates a WordPress session and sets its auth
cookies; it must run before output. The plugin handles this automatically at
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

## Build a plugin ZIP

```sh
python3 tools/package.py
```

Creates `dist/wp-support-access.zip` with an explicit runtime file allowlist.
Development files and tests are excluded.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
