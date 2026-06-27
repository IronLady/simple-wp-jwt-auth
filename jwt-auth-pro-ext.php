<?php
/**
 * Plugin bootstrap file.
 *
 * @wordpress-plugin
 * Plugin Name:       JWT Auth Pro Extensions
 * Plugin URI:        https://2damcreative.com
 * Description:       Adds refresh tokens, token rotation, server-side revocation/logout, and rate limiting on top of "JWT Authentication for WP-API".
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Requires Plugins:  jwt-authentication-for-wp-rest-api
 * Author:            2DAM Creative
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       jwt-auth-ext
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

define( 'JWT_AUTH_EXT_VERSION', '1.0.0' );
define( 'JWT_AUTH_EXT_DB_VERSION', '1' );
define( 'JWT_AUTH_EXT_FILE', __FILE__ );
define( 'JWT_AUTH_EXT_PATH', plugin_dir_path( __FILE__ ) );

require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-jwt.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-tokens.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-claims.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-guard.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-rate-limit.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-routes.php';
require_once JWT_AUTH_EXT_PATH . 'includes/class-ext-bootstrap.php';

/**
 * Create / migrate the refresh-token table on activation.
 *
 * @return void
 */
function jwt_auth_ext_activate() {
	Ext_Tokens::install_table();
}
register_activation_hook( __FILE__, 'jwt_auth_ext_activate' );

/**
 * Clear our scheduled cleanup on deactivation.
 *
 * @return void
 */
function jwt_auth_ext_deactivate() {
	$timestamp = wp_next_scheduled( Ext_Bootstrap::CRON_HOOK );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, Ext_Bootstrap::CRON_HOOK );
	}
}
register_deactivation_hook( __FILE__, 'jwt_auth_ext_deactivate' );

/**
 * Boot the extension once all plugins are loaded so the base plugin's
 * classes/filters are guaranteed to exist.
 *
 * @return void
 */
function jwt_auth_ext_run() {
	( new Ext_Bootstrap() )->run();
}
add_action( 'plugins_loaded', 'jwt_auth_ext_run' );
