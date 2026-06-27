<?php
/**
 * Wires all extension components together once WordPress + the base plugin are
 * loaded. No-ops gracefully if the base plugin is inactive or misconfigured.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Bootstrap {

	/** Daily cleanup cron hook. */
	const CRON_HOOK = 'jwt_auth_ext_purge_expired';

	/**
	 * Register everything.
	 *
	 * @return void
	 */
	public function run() {
		// DB migration safety net for existing installs.
		add_action( 'admin_init', [ Ext_Tokens::class, 'maybe_upgrade' ] );

		// Schedule daily cleanup of expired refresh tokens.
		add_action( 'init', [ $this, 'schedule_cron' ] );
		add_action( self::CRON_HOOK, [ Ext_Tokens::class, 'purge_expired' ] );

		// The base plugin must be present for the rest to be meaningful.
		if ( ! $this->base_plugin_active() ) {
			return;
		}

		( new Ext_Claims() )->register();
		( new Ext_Guard() )->register();
		( new Ext_Rate_Limit() )->register();
		( new Ext_Routes() )->register();
	}

	/**
	 * Ensure the daily cron event exists.
	 *
	 * @return void
	 */
	public function schedule_cron() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Detect the base "JWT Authentication for WP-API" plugin.
	 *
	 * @return bool
	 */
	private function base_plugin_active() {
		// The base plugin defines this class for its public hooks.
		return class_exists( 'Jwt_Auth_Public' );
	}
}
