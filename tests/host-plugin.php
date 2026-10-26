<?php
/**
 * Plugin Name: Disposable embedding host
 * Description: Integration fixture only; never included in the runtime archive.
 */
if (!defined('ABSPATH')) {
    exit;
}

require_once WP_PLUGIN_DIR . '/wp-support-access/src/SupportAccess.php';

$wpsaHost = new \NLProduction\WordPress\SupportAccess\SupportAccess(get_option('wpsa_test_redirect', []));
$wpsaHost->register();
register_activation_hook(__FILE__, [$wpsaHost, 'initialize']);
register_deactivation_hook(__FILE__, [$wpsaHost, 'deactivate']);

add_action('admin_menu', static function () {
    add_menu_page('Host settings', 'Host settings', 'manage_options', 'wpsa-host-settings', static function () {
        echo '<div class="wrap"><h1>Embedding host settings reached</h1></div>';
    });
});
