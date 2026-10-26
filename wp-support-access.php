<?php
/**
 * Plugin Name: WP Support Access
 * Plugin URI: https://github.com/nlproduction/wp-support-access
 * Update URI: https://github.com/nlproduction/wp-support-access
 * Description: One-click temporary WordPress administrator access with expiring, revocable magic links.
 * Version: 1.1.0
 * Requires at least: 5.9
 * Requires PHP: 7.4
 * Author: Northern Lights Production
 * Author URI: https://github.com/nlproduction
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * Text Domain: wp-support-access
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/src/SupportAccess.php';
require_once __DIR__ . '/src/AdminPage.php';

$wpsaService = new \NLProduction\WordPress\SupportAccess\SupportAccess();
$wpsaService->register();
(new \NLProduction\WordPress\SupportAccess\AdminPage($wpsaService))->register();

register_activation_hook(__FILE__, [$wpsaService, 'initialize']);
register_deactivation_hook(__FILE__, static function ($networkWide) use ($wpsaService) {
    if (is_multisite() && $networkWide) {
        $offset = 0;
        do {
            $ids = get_sites(['fields' => 'ids', 'number' => 100, 'offset' => $offset]);
            foreach ($ids as $id) {
                switch_to_blog((int) $id);
                try {
                    if (get_option('wpsa_schema_version') === '1') {
                        $wpsaService->deactivate();
                    }
                } finally {
                    restore_current_blog();
                }
            }
            $offset += 100;
        } while (count($ids) === 100);
    } else {
        $wpsaService->deactivate();
    }
});
