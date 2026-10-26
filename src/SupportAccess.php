<?php

namespace NLProduction\WordPress\SupportAccess;

/** WordPress-only service. Each grant owns one account and its sessions. */
final class SupportAccess
{
    public const USER_META = '_wpsa_grant';
    public const CRON_HOOK = 'wpsa_cleanup';
    public const DEFAULT_TTL = 86400;
    public const MAX_TTL = 604800;

    private $registered = false;
    private $redirectTo;

    /** @param array{redirect_to?: string} $options Destination within this site's wp-admin. */
    public function __construct(array $options = [])
    {
        $redirectTo = $options['redirect_to'] ?? '';
        if (!is_string($redirectTo)) {
            throw new \InvalidArgumentException('redirect_to must be a string.');
        }
        // Resolve at login time: WordPress pluggables and the current site/HTTPS
        // context may not be available yet while the host plugin is loading.
        $this->redirectTo = $redirectTo;
    }

    public function register(): void
    {
        if ($this->registered) {
            return;
        }
        $this->registered = true;
        add_action('init', [$this, 'initialize']);
        add_action('rest_api_init', [$this, 'registerRoutes']);
        add_action('login_form_wpsa_login', [$this, 'handleLogin']);
        add_action(self::CRON_HOOK, [$this, 'cleanup']);
        add_filter('determine_current_user', [$this, 'guardSession'], 100);
        add_filter('authenticate', [$this, 'guardAuthentication'], 100, 3);
        add_filter('auth_cookie_expiration', [$this, 'cookieLifetime'], 100, 3);
    }

    public function initialize(): void
    {
        if (get_option('wpsa_schema_version') !== '1') {
            $this->install();
        }
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 300, 'hourly', self::CRON_HOOK);
        }
    }

    public function install(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = $this->table();
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$table} (
            id varchar(32) NOT NULL,
            token_hash varchar(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            created_by bigint(20) unsigned NOT NULL,
            label varchar(191) NOT NULL DEFAULT '',
            created_at bigint(20) unsigned NOT NULL,
            expires_at bigint(20) unsigned NOT NULL,
            last_used_at bigint(20) unsigned DEFAULT NULL,
            revoked_at bigint(20) unsigned DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY token_hash (token_hash),
            KEY expires_at (expires_at)
        ) {$charset};");
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) !== $table) {
            throw new \RuntimeException('Unable to install support-access storage.');
        }
        update_option('wpsa_schema_version', '1', false);
    }

    /** Support accounts cannot delegate their access by minting new grants. */
    public function canManage(): bool
    {
        return current_user_can('manage_options')
            && !get_user_meta(get_current_user_id(), self::USER_META, true);
    }

    /** @return array|\WP_Error Raw token and URL exist only in this response. */
    public function issue(array $options = [])
    {
        global $wpdb;
        if (!$this->canManage()) {
            return $this->error('forbidden', 'Only a site administrator can grant support access.', 403);
        }
        $ttl = $options['ttl'] ?? self::DEFAULT_TTL;
        if (!is_int($ttl) || $ttl < 60 || $ttl > self::MAX_TTL) {
            return $this->error('invalid_ttl', 'Lifetime must be an integer between 60 and 604800 seconds.', 400);
        }
        if (isset($options['label']) && !is_string($options['label'])) {
            return $this->error('invalid_label', 'Label must be a string.', 400);
        }
        $id = bin2hex(random_bytes(16));
        $raw = bin2hex(random_bytes(32));
        $now = time();
        $row = [
            'id' => $id,
            'token_hash' => hash('sha256', $raw),
            'user_id' => 0,
            'created_by' => get_current_user_id(),
            'label' => sanitize_text_field($options['label'] ?? 'Support'),
            'created_at' => $now,
            'expires_at' => $now + $ttl,
        ];
        if (strlen($row['label']) > 191) {
            return $this->error('invalid_label', 'Label must fit in 191 UTF-8 bytes.', 400);
        }
        if ($wpdb->insert($this->table(), $row) !== 1) {
            return $this->error('storage_error', 'Unable to store support access.', 500);
        }
        // Never reuse a customer account or set its password to the bearer token.
        $login = 'wpsa_' . $id;
        $userId = wp_insert_user([
            'user_login' => $login,
            'user_pass' => wp_generate_password(64, true, true),
            'user_email' => $login . '@support.invalid',
            'display_name' => $row['label'] ?: 'Temporary support',
            // Grant capabilities only after the storage/account binding succeeds.
            'role' => '',
            'locale' => 'en_US',
            'meta_input' => [self::USER_META => ['blog_id' => get_current_blog_id(), 'grant_id' => $id]],
        ]);
        if (is_wp_error($userId)) {
            $wpdb->update($this->table(), ['revoked_at' => $now], ['id' => $id]);
            return $this->error('account_error', 'Unable to create the temporary support account.', 500);
        }
        $row['user_id'] = (int) $userId;
        if (!$this->ownsUser($row) || $wpdb->update($this->table(), ['user_id' => $userId], ['id' => $id]) !== 1) {
            $wpdb->update($this->table(), ['revoked_at' => $now], ['id' => $id]);
            $this->retireUser($row);
            return $this->error('storage_error', 'Unable to finalize support access.', 500);
        }
        $user = new \WP_User($userId);
        $user->set_role('administrator');
        if (!user_can($userId, 'manage_options')) {
            $this->retire($row);
            return $this->error('account_error', 'Unable to grant the temporary account administrator access.', 500);
        }
        $result = $this->present($row);
        $result['token'] = $raw;
        $result['url'] = add_query_arg(['action' => 'wpsa_login', 'wpsa_token' => $raw], site_url('wp-login.php', 'login'));
        return $result;
    }

    /** @return array|\WP_Error Safe metadata; never includes token/hash/URL. */
    public function grants(int $limit = 100, int $offset = 0)
    {
        global $wpdb;
        if (!$this->canManage()) {
            return $this->error('forbidden', 'Only a site administrator can list support access.', 403);
        }
        $rows = $wpdb->get_results($wpdb->prepare(
            'SELECT * FROM ' . $this->table() . ' ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d',
            max(1, min(100, $limit)), max(0, $offset)
        ), ARRAY_A);
        if ($wpdb->last_error) {
            return $this->error('storage_error', 'Unable to read support access.', 500);
        }
        return array_map([$this, 'present'], $rows);
    }

    /** @return true|\WP_Error */
    public function revoke(string $id)
    {
        if (!$this->canManage()) {
            return $this->error('forbidden', 'Only a site administrator can revoke support access.', 403);
        }
        $row = $this->find($id);
        return $row ? $this->retire($row) : $this->error('not_found', 'Support access was not found.', 404);
    }

    /** Validate a bearer token without logging in. No raw token is persisted. */
    public function validate(string $raw)
    {
        global $wpdb;
        if (!preg_match('/\A[a-f0-9]{64}\z/D', $raw)) {
            return $this->error('invalid_link', 'This access link is invalid, expired or revoked.', 403);
        }
        $row = $wpdb->get_row($wpdb->prepare(
            'SELECT * FROM ' . $this->table() . ' WHERE token_hash = %s', hash('sha256', $raw)
        ), ARRAY_A);
        if (!$row || !$this->active($row) || !$this->ownsUser($row)) {
            return $this->error('invalid_link', 'This access link is invalid, expired or revoked.', 403);
        }
        return $this->present($row);
    }

    /** @return array|\WP_Error Creates an ordinary WordPress session cookie. */
    public function login(string $raw)
    {
        global $wpdb;
        $grant = $this->validate($raw);
        if (is_wp_error($grant)) {
            return $grant;
        }
        // Recheck the active state in the same write that records use.
        $updated = $wpdb->query($wpdb->prepare(
            'UPDATE ' . $this->table() . ' SET last_used_at = %d WHERE id = %s AND revoked_at IS NULL AND expires_at > %d',
            time(), $grant['id'], time()
        ));
        if ($updated === false || !$this->isActiveUser($grant['user_id'])) {
            return $this->error('invalid_link', 'This access link is invalid, expired or revoked.', 403);
        }
        // Explicit expiration also bounds the session store, independent of cookie filters.
        $manager = \WP_Session_Tokens::get_instance($grant['user_id']);
        $session = $manager->create($grant['expires_at']);
        wp_set_current_user($grant['user_id']);
        wp_set_auth_cookie($grant['user_id'], false, is_ssl(), $session);
        // A concurrent revoke/expiry must not resurrect a support session.
        if (!$this->isActiveUser($grant['user_id'])) {
            $manager->destroy($session);
            wp_clear_auth_cookie();
            wp_set_current_user(0);
            return $this->error('invalid_link', 'This access link is invalid, expired or revoked.', 403);
        }
        do_action('wp_login', get_userdata($grant['user_id'])->user_login, get_userdata($grant['user_id']));
        return $grant;
    }

    public function handleLogin(): void
    {
        nocache_headers();
        header('Referrer-Policy: no-referrer');
        header('X-Robots-Tag: noindex, nofollow');
        header('Cache-Control: no-store, private');
        $raw = isset($_GET['wpsa_token']) && is_string($_GET['wpsa_token']) ? wp_unslash($_GET['wpsa_token']) : '';
        $result = $this->login($raw);
        if (is_wp_error($result)) {
            wp_die(esc_html($result->get_error_message()), 'Support access', ['response' => 403]);
        }
        // Redirect target is entirely server-owned; never reflect an incoming redirect URL.
        wp_safe_redirect($this->redirectUrl());
        exit;
    }

    private function redirectUrl(): string
    {
        $fallback = admin_url();
        $target = $this->redirectTo;
        if ($target === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $target)) {
            return $fallback;
        }
        $parts = wp_parse_url($target);
        if ($parts === false || isset($parts['user']) || isset($parts['pass'])) {
            return $fallback;
        }
        if (!isset($parts['scheme']) && !isset($parts['host']) && $target[0] !== '/') {
            $target = admin_url($target);
            $parts = wp_parse_url($target);
        }
        $base = wp_parse_url($fallback);
        if (!$parts || !isset($parts['scheme'], $parts['host'])
            || strtolower($parts['scheme']) !== strtolower($base['scheme'])
            || strtolower($parts['host']) !== strtolower($base['host'])
            || ($parts['port'] ?? null) !== ($base['port'] ?? null)) {
            return $fallback;
        }
        $path = rawurldecode($parts['path'] ?? '');
        $adminPath = rawurldecode($base['path']);
        // Check the directory boundary and decoded traversal before redirecting.
        // Reject residual %-encoding so repeated decoding cannot change the path.
        if (strpos($path, $adminPath) !== 0
            || preg_match('~(?:^|/)\.{1,2}(?:/|$)|[\x00-\x20\x7f\\\\%]~', $path)) {
            return $fallback;
        }
        return $target;
    }

    public function guardSession($userId)
    {
        if ($userId && get_user_meta((int) $userId, self::USER_META, true) && !$this->isActiveUser((int) $userId)) {
            return false;
        }
        return $userId;
    }

    public function guardAuthentication($user, $username = '', $password = '')
    {
        if ($user instanceof \WP_User && $this->guardSession($user->ID) === false) {
            return $this->error('access_expired', 'This support account is no longer active.', 403);
        }
        return $user;
    }

    public function cookieLifetime($seconds, $userId, $remember = false): int
    {
        $owner = get_user_meta((int) $userId, self::USER_META, true);
        if (!$owner) {
            return (int) $seconds;
        }
        $row = $this->ownedGrant((int) $userId);
        return $row && $this->active($row) ? max(1, min((int) $seconds, (int) $row['expires_at'] - time())) : 1;
    }

    /** Expiry is enforced on every request, even if WP-Cron never runs. */
    public function cleanup(): void
    {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            'SELECT * FROM ' . $this->table() . ' WHERE user_id <> 0 AND (expires_at <= %d OR revoked_at IS NOT NULL) LIMIT 100', time()
        ), ARRAY_A);
        foreach ($rows ?: [] as $row) {
            $this->retire($row);
        }
    }

    /** Call from the embedding plugin's deactivation hook for the current site. */
    public function deactivate(): void
    {
        global $wpdb;
        // Revoke in one write before processing account cleanup in bounded batches.
        if ($wpdb->query('UPDATE ' . $this->table() . ' SET revoked_at = COALESCE(revoked_at, ' . time() . ')') === false) {
            throw new \RuntimeException('Unable to revoke support access during deactivation.');
        }
        do {
            $rows = $wpdb->get_results('SELECT * FROM ' . $this->table() . ' WHERE user_id <> 0 LIMIT 100', ARRAY_A);
            $progress = false;
            foreach ($rows ?: [] as $row) {
                if ($this->retire($row) === true) {
                    $progress = true;
                }
            }
        } while (count($rows ?: []) === 100 && $progress);
        wp_clear_scheduled_hook(self::CRON_HOOK);
    }

    public function registerRoutes(): void
    {
        $permission = [$this, 'canManage'];
        register_rest_route('wp-support-access/v1', '/grants', [
            [
                'methods' => 'GET', 'permission_callback' => $permission,
                'callback' => function ($request) {
                    return $this->response($this->grants((int) ($request['limit'] ?? 100), (int) ($request['offset'] ?? 0)));
                },
            ],
            [
                'methods' => 'POST', 'permission_callback' => $permission,
                'callback' => function ($request) {
                    $params = $request->get_json_params();
                    return $this->response($this->issue(is_array($params) ? $params : []), 201);
                },
            ],
        ]);
        register_rest_route('wp-support-access/v1', '/grants/(?P<id>[a-f0-9]{32})', [
            'methods' => 'DELETE', 'permission_callback' => $permission,
            'callback' => function ($request) {
                $result = $this->revoke($request['id']);
                return $this->response(is_wp_error($result) ? $result : ['revoked' => true]);
            },
        ]);
    }

    private function response($data, int $status = 200)
    {
        if (is_wp_error($data)) {
            return $data;
        }
        $response = new \WP_REST_Response($data, $status);
        $response->header('Cache-Control', 'no-store, private');
        return $response;
    }

    private function table(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'wpsa_grants';
    }

    private function find(string $id): ?array
    {
        global $wpdb;
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $id)) {
            return null;
        }
        return $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $this->table() . ' WHERE id = %s', $id), ARRAY_A) ?: null;
    }

    private function active(array $row): bool
    {
        return empty($row['revoked_at']) && (int) $row['expires_at'] > time() && (int) $row['user_id'] > 0;
    }

    private function ownsUser(array $row): bool
    {
        $owner = get_user_meta((int) $row['user_id'], self::USER_META, true);
        return is_array($owner)
            && (int) ($owner['blog_id'] ?? 0) === get_current_blog_id()
            && ($owner['grant_id'] ?? '') === $row['id']
            && (bool) get_userdata((int) $row['user_id'])
            && !(is_multisite() && is_super_admin((int) $row['user_id']));
    }

    private function ownedGrant(int $userId): ?array
    {
        $owner = get_user_meta($userId, self::USER_META, true);
        if (!is_array($owner) || (int) ($owner['blog_id'] ?? 0) !== get_current_blog_id()) {
            return null;
        }
        $row = $this->find((string) ($owner['grant_id'] ?? ''));
        return $row && (int) $row['user_id'] === $userId && $this->ownsUser($row) ? $row : null;
    }

    private function isActiveUser(int $userId): bool
    {
        $row = $this->ownedGrant($userId);
        return $row && $this->active($row) && is_user_member_of_blog($userId, get_current_blog_id());
    }

    private function retire(array $row)
    {
        global $wpdb;
        // First invalidate the grant; session guard covers partial cleanup failures.
        if ($wpdb->query($wpdb->prepare(
            'UPDATE ' . $this->table() . ' SET revoked_at = COALESCE(revoked_at, %d) WHERE id = %s', time(), $row['id']
        )) === false) {
            return $this->error('storage_error', 'Unable to revoke support access.', 500);
        }
        if (!$this->retireUser($row)) {
            return $this->error('cleanup_error', 'Access revoked, but account cleanup needs a retry.', 500);
        }
        if ($wpdb->update($this->table(), ['user_id' => 0], ['id' => $row['id']]) === false) {
            return $this->error('cleanup_error', 'Access revoked, but cleanup metadata needs a retry.', 500);
        }
        return true;
    }

    private function retireUser(array $row): bool
    {
        $userId = (int) $row['user_id'];
        if (!$userId || !get_userdata($userId)) {
            return true;
        }
        if (!$this->ownsUser($row)) {
            return false;
        }
        \WP_Session_Tokens::get_instance($userId)->destroy_all();
        $creator = (int) $row['created_by'];
        // Never delete support-authored content if the original admin disappeared.
        // Retain a disabled, role-less account instead, keeping the ownership marker.
        if (!$creator || $creator === $userId || !get_userdata($creator) || !is_user_member_of_blog($creator)) {
            $user = new \WP_User($userId);
            $user->set_role('');
            return false;
        }
        require_once ABSPATH . 'wp-admin/includes/user.php';
        // On multisite wp_delete_user removes only this site's membership and
        // reassigns this site's content. Never call network-wide wpmu_delete_user.
        return wp_delete_user($userId, $creator);
    }

    private function present(array $row): array
    {
        return [
            'id' => $row['id'],
            'user_id' => (int) $row['user_id'],
            'created_by' => (int) $row['created_by'],
            'label' => $row['label'],
            'created_at' => (int) $row['created_at'],
            'expires_at' => (int) $row['expires_at'],
            'last_used_at' => isset($row['last_used_at']) ? (int) $row['last_used_at'] : null,
            'revoked_at' => isset($row['revoked_at']) ? (int) $row['revoked_at'] : null,
            'active' => $this->active($row),
        ];
    }

    private function error(string $code, string $message, int $status): \WP_Error
    {
        return new \WP_Error('wpsa_' . $code, $message, ['status' => $status]);
    }
}
