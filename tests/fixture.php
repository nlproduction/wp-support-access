<?php
/** CLI-only fixture, always bootstrapped from a new disposable site. */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$root = getenv('WPSA_TEST_ROOT');
if (!$root || realpath($root) !== $root || strpos(basename($root), 'wpsa-test-') !== 0
    || !is_file($root . '/owned-fixture') || !is_file($root . '/wp/wp-config.php')) {
    throw new RuntimeException('An owned temporary test site is required.');
}
if (($argv[1] ?? '') === 'install') {
    define('WP_INSTALLING', true);
}
require $root . '/wp/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once WP_PLUGIN_DIR . '/wp-support-access/src/SupportAccess.php';
$command = $argv[1] ?? '';

if ($command === 'install') {
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    wp_install('Support access test', 'testadmin', 'admin@example.invalid', false, '', 'disposable-admin-password');
    $result = activate_plugin('wp-support-access/wp-support-access.php');
    if (is_wp_error($result)) {
        throw new RuntimeException($result->get_error_message());
    }
    // The plugin wasn't active during this process's bootstrap.
    require_once WP_PLUGIN_DIR . '/wp-support-access/src/SupportAccess.php';
    echo "installed\n";
    exit;
}
$service = new \NLProduction\WordPress\SupportAccess\SupportAccess();

function expect($condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

if ($command === 'contracts') {
    wp_set_current_user(1);
    expect($service->canManage(), 'Site administrator must manage grants');
    $editor = wp_insert_user(['user_login' => 'testeditor', 'role' => 'editor', 'user_pass' => 'disposable-editor-password']);
    wp_set_current_user($editor);
    expect(is_wp_error($service->issue()), 'Editor cannot issue');
    expect(is_wp_error($service->grants()), 'Editor cannot list');
    expect(is_wp_error($service->revoke(str_repeat('a', 32))), 'Editor cannot revoke');
    wp_set_current_user(0);
    expect(is_wp_error($service->issue()), 'Guest cannot issue');
    wp_set_current_user(1);
    foreach ([0, 59, 604801, '3600', 1.5, true] as $ttl) {
        expect(is_wp_error($service->issue(['ttl' => $ttl])), 'Invalid TTL accepted');
    }
    expect(is_wp_error($service->issue(['label' => ['bad']])), 'Array label accepted');
    expect(is_wp_error($service->issue(['label' => str_repeat('x', 192)])), 'Long label accepted');
    // Existing names/emails must never be adopted as support accounts.
    $existing = wp_insert_user(['user_login' => 'mapsvg', 'user_email' => 'support@mapsvg.example', 'user_pass' => 'original-password', 'role' => 'subscriber']);
    $oldHash = get_userdata($existing)->user_pass;
    $a = $service->issue(['label' => '<b>Ticket 123</b>', 'ttl' => 3600]);
    $b = $service->issue();
    expect(!is_wp_error($a) && !is_wp_error($b), 'Grant issuance failed');
    expect($a['user_id'] !== $b['user_id'], 'Grants must have isolated users');
    expect($a['label'] === 'Ticket 123', 'Label is not sanitized');
    expect(strlen($a['token']) === 64, 'Token entropy/format');
    expect(!wp_check_password($a['token'], get_userdata($a['user_id'])->user_pass, $a['user_id']), 'Token must not be account password');
    global $wpdb;
    $stored = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $wpdb->prefix . 'wpsa_grants WHERE id = %s', $a['id']), ARRAY_A);
    expect($stored['token_hash'] === hash('sha256', $a['token']), 'Hash storage');
    expect(strpos(wp_json_encode($stored), $a['token']) === false, 'Raw token persisted');
    $list = $service->grants();
    expect(count($list) === 2 && !isset($list[0]['token'], $list[0]['url'], $list[0]['token_hash']), 'List discloses a secret');
    expect(count($service->grants(1, 1)) === 1, 'Grant paging');
    foreach (['', str_repeat('a', 63), str_repeat('a', 65), str_repeat('A', 64), 'a\' OR 1=1 --'] as $bad) {
        expect(is_wp_error($service->validate($bad)), 'Malformed link accepted');
    }
    expect(!is_wp_error($service->validate($a['token'])), 'Valid token rejected');
    wp_set_current_user($a['user_id']);
    expect(!$service->canManage() && is_wp_error($service->issue()), 'Support must not extend/delegate access');
    wp_set_current_user(1);
    expect($service->cookieLifetime(100000, $a['user_id']) <= 3600, 'Cookie outlives grant');
    expect($service->cookieLifetime(900, 1) === 900, 'Normal administrator cookie changed');
    $post = wp_insert_post(['post_title' => 'Support-authored content', 'post_author' => $a['user_id'], 'post_status' => 'publish']);
    expect($service->revoke($a['id']) === true, 'Revoke failed');
    expect(is_wp_error($service->validate($a['token'])), 'Revoked token accepted');
    expect(!get_userdata($a['user_id']), 'Single-site support account remains');
    expect((int) get_post($post)->post_author === 1, 'Support content lost instead of reassigned');
    expect(!is_wp_error($service->validate($b['token'])), 'Revoking A invalidated B');
    expect($service->revoke($a['id']) === true, 'Revoke must be idempotent');
    expect(is_wp_error($service->revoke(str_repeat('0', 32))), 'Missing revoke should be 404');
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['expires_at' => time() - 1], ['id' => $b['id']]);
    expect(is_wp_error($service->validate($b['token'])), 'Expired token accepted before cron');
    expect($service->guardSession($b['user_id']) === false, 'Expired session accepted before cron');
    expect(is_wp_error($service->guardAuthentication(get_userdata($b['user_id']))), 'Expired password authentication accepted');
    $service->cleanup();
    expect(!get_userdata($b['user_id']), 'Expired account not cleaned');
    // Corrupt ownership cannot cause takeover/deletion of a real customer account.
    $c = $service->issue();
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['user_id' => $existing], ['id' => $c['id']]);
    expect(is_wp_error($service->validate($c['token'])), 'Unowned user accepted');
    expect(is_wp_error($service->revoke($c['id'])), 'Ownership mismatch must report cleanup failure');
    expect(get_userdata($existing)->user_pass === $oldHash, 'Existing account was modified');
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['user_id' => $c['user_id']], ['id' => $c['id']]);
    expect($service->revoke($c['id']) === true, 'Ownership recovery cleanup');
    $d = $service->issue();
    $dPost = wp_insert_post(['post_title' => 'Preserved orphan content', 'post_author' => $d['user_id'], 'post_status' => 'publish']);
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['created_by' => 0], ['id' => $d['id']]);
    expect(is_wp_error($service->revoke($d['id'])), 'Missing issuer cleanup must be reported');
    expect(get_userdata($d['user_id'])->roles === [], 'Missing issuer support user retains a role');
    expect(get_post($dPost) && is_wp_error($service->validate($d['token'])), 'Missing issuer content lost or token valid');
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['created_by' => 1], ['id' => $d['id']]);
    expect($service->revoke($d['id']) === true, 'Missing issuer recovery failed');
    // Storage read failures fail closed, without issuing a session.
    $prior = $wpdb->suppress_errors(true);
    $wpdb->query('RENAME TABLE ' . $wpdb->prefix . 'wpsa_grants TO ' . $wpdb->prefix . 'wpsa_offline');
    expect(is_wp_error($service->validate($a['token'])), 'Storage failure accepted token');
    $wpdb->query('RENAME TABLE ' . $wpdb->prefix . 'wpsa_offline TO ' . $wpdb->prefix . 'wpsa_grants');
    $wpdb->suppress_errors($prior);
    echo "PASS PHP lifecycle, ownership, authorization, hash-only storage, expiry, paging, content reassignment, storage failure\n";
    exit;
}

if ($command === 'expire') {
    global $wpdb;
    $wpdb->update($wpdb->prefix . 'wpsa_grants', ['expires_at' => time() - 1], ['id' => $argv[2]]);
    exit;
}
if ($command === 'sessions') {
    echo wp_json_encode(WP_Session_Tokens::get_instance((int) $argv[2])->get_all());
    exit;
}
if ($command === 'deactivate') {
    deactivate_plugins('wp-support-access/wp-support-access.php');
    echo "deactivated\n";
    exit;
}
if ($command === 'state') {
    global $wpdb;
    echo wp_json_encode([
        'active' => $wpdb->get_var('SELECT COUNT(*) FROM ' . $wpdb->prefix . 'wpsa_grants WHERE revoked_at IS NULL'),
        'support_users' => $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM ' . $wpdb->usermeta . ' WHERE meta_key = %s', $service::USER_META)),
    ]);
    exit;
}
if ($command === 'network-install') {
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    global $wpdb;
    foreach ($wpdb->tables('ms_global') as $name => $table) {
        $wpdb->$name = $table;
    }
    dbDelta(wp_get_db_schema('ms_global'));
    $result = populate_network(1, '127.0.0.1', 'admin@example.invalid', 'Disposable network', '/', false);
    expect(!is_wp_error($result) || $result->get_error_code() === 'no_wildcard_dns', 'Network initialization failed');
    echo "installed disposable network\n";
    exit;
}
if ($command === 'multisite') {
    expect(is_multisite(), 'Multisite constants not loaded');
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    // Complete the ordinary network schema upgrade after enabling MULTISITE.
    dbDelta(wp_get_db_schema('global'));
    wp_set_current_user(1);
    $result = activate_plugin('wp-support-access/wp-support-access.php', '', true);
    expect(!is_wp_error($result), 'Network activation failed');
    $second = wpmu_create_blog('127.0.0.1', '/second/', 'Second site', 1);
    expect(!is_wp_error($second), 'Second site creation failed');
    $a = $service->issue();
    expect(!is_wp_error($a), 'Main site multisite issuance failed');
    expect(!is_super_admin($a['user_id']), 'Support user became network super admin');
    expect(!is_wp_error($service->validate($a['token'])), 'Main-site token rejected');
    switch_to_blog($second);
    $service->initialize();
    wp_set_current_user(1);
    expect(is_wp_error($service->validate($a['token'])), 'Cross-site token accepted');
    expect($service->guardSession($a['user_id']) === false, 'Cross-site support session accepted');
    $b = $service->issue();
    expect(!is_wp_error($b), 'Second site issuance failed');
    $bPost = wp_insert_post(['post_title' => 'Second-site support content', 'post_author' => $b['user_id'], 'post_status' => 'publish']);
    expect($service->revoke($b['id']) === true, 'Second site revoke failed');
    expect(get_userdata($b['user_id']) && !is_user_member_of_blog($b['user_id'], $second), 'Network identity was deleted or site membership retained');
    expect((int) get_post($bPost)->post_author === 1, 'Second-site support content lost');
    $c = $service->issue();
    expect(!is_wp_error($c), 'Second-site reissue failed');
    restore_current_blog();
    wp_set_current_user(1);
    expect(!is_wp_error($service->validate($a['token'])), 'Other-site revoke affected main-site grant');
    deactivate_plugins('wp-support-access/wp-support-access.php', false, true);
    expect(is_wp_error($service->validate($a['token'])), 'Network deactivation retained main-site grant');
    expect(!is_user_member_of_blog($a['user_id'], 1), 'Main-site support membership retained');
    switch_to_blog($second);
    expect(is_wp_error($service->validate($c['token'])), 'Network deactivation retained second-site grant');
    expect(!is_user_member_of_blog($c['user_id'], $second), 'Second-site support membership retained');
    restore_current_blog();
    echo "PASS real multisite issuance, site isolation, no super admin, membership/content cleanup and network deactivation\n";
    exit;
}
throw new RuntimeException('Unknown fixture command.');
