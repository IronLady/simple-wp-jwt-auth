<?php
/**
 * PHPUnit bootstrap. Loads the WordPress test suite, then BOTH the base
 * "JWT Authentication for WP-API" plugin and this extension plugin.
 */

define( 'DOING_TESTS', true );

if ( getenv( 'WP_CLI_PACKAGES_DIR' ) ) {
	require_once '/var/www/html/wp-tests-config.php';
	require_once '/var/www/html/wp-includes/functions.php';
	require_once '/var/www/html/wp-admin/includes/plugin.php';
} else {
	$_tests_dir = getenv( 'WP_TESTS_DIR' );
	if ( ! $_tests_dir ) {
		$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
	}

	if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
		echo "Could not find $_tests_dir/includes/functions.php, have you run bin/install-wp-tests.sh ?" . PHP_EOL;
		exit( 1 );
	}

	require_once $_tests_dir . '/includes/functions.php';
	require $_tests_dir . '/includes/bootstrap.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

/**
 * Resolve the base plugin's main file from common install locations.
 *
 * @return string|null
 */
function jwt_auth_ext_locate_base_plugin() {
	$candidates = [
		getenv( 'JWT_AUTH_BASE_PLUGIN' ) ?: '',
		WP_PLUGIN_DIR . '/jwt-authentication-for-wp-rest-api/jwt-auth.php',
		WP_PLUGIN_DIR . '/wp-api-jwt-auth/jwt-auth.php',
		dirname( __DIR__ ) . '/vendor/wp-plugins/jwt-authentication-for-wp-rest-api/jwt-auth.php',
	];

	foreach ( $candidates as $path ) {
		if ( $path && file_exists( $path ) ) {
			return $path;
		}
	}

	return null;
}

/**
 * Load both plugins before the WP test harness finishes booting.
 */
function jwt_auth_ext_load_plugins() {
	if ( ! defined( 'JWT_AUTH_SECRET_KEY' ) ) {
		define( 'JWT_AUTH_SECRET_KEY', 'test-secret-key-for-phpunit' );
	}

	$base = jwt_auth_ext_locate_base_plugin();
	if ( $base ) {
		require_once $base;
	} else {
		echo "WARNING: base JWT plugin not found; integration tests will be skipped." . PHP_EOL;
	}

	require_once dirname( __DIR__ ) . '/jwt-auth-pro-ext.php';
}
add_action( 'muplugins_loaded', 'jwt_auth_ext_load_plugins' );

// Match the base plugin's test environment.
add_filter( 'jwt_auth_rate_limit_headers_enabled', '__return_false' );
