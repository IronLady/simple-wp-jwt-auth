<?php
/**
 * Refresh-token repository + access-token revocation set.
 *
 * Refresh tokens are opaque random strings. Only their SHA-256 hash is stored;
 * the raw value is returned to the client once and never persisted.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Tokens {

	/** Default refresh-token lifetime: 14 days. */
	const DEFAULT_TTL = 1209600;

	/**
	 * Fully-qualified table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;

		return $wpdb->prefix . 'jwt_auth_ext_refresh_tokens';
	}

	/**
	 * Create / migrate the table. Safe to call repeatedly (dbDelta is idempotent).
	 *
	 * @return void
	 */
	public static function install_table() {
		global $wpdb;

		$table           = self::table();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NOT NULL,
			jti CHAR(36) NOT NULL,
			token_hash CHAR(64) NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			last_used_at DATETIME NULL,
			user_agent VARCHAR(255) NULL,
			ip VARCHAR(45) NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY jti (jti),
			KEY token_hash (token_hash),
			KEY user_id (user_id),
			KEY expires_at (expires_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( 'jwt_auth_ext_db_version', JWT_AUTH_EXT_DB_VERSION );
	}

	/**
	 * Run the table migration if the stored DB version is out of date.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'jwt_auth_ext_db_version' ) !== JWT_AUTH_EXT_DB_VERSION ) {
			self::install_table();
		}
	}

	/**
	 * Hash an opaque refresh token for storage / lookup.
	 *
	 * @param string $raw Raw token.
	 *
	 * @return string
	 */
	private static function hash( $raw ) {
		return hash( 'sha256', $raw );
	}

	/**
	 * Refresh-token lifetime in seconds (filterable).
	 *
	 * @return int
	 */
	public static function ttl() {
		return (int) apply_filters( 'jwt_auth_ext_refresh_ttl', self::DEFAULT_TTL );
	}

	/**
	 * Issue a new refresh token for a user and persist its hash.
	 *
	 * @param int $user_id User ID.
	 *
	 * @return array{raw:string,jti:string,expires_at:int} Raw token returned ONCE.
	 */
	public static function create_refresh_token( $user_id ) {
		global $wpdb;

		$raw        = bin2hex( random_bytes( 32 ) );
		$jti        = wp_generate_uuid4();
		$now        = time();
		$expires_at = $now + self::ttl();

		$wpdb->insert(
			self::table(),
			[
				'user_id'    => (int) $user_id,
				'jti'        => $jti,
				'token_hash' => self::hash( $raw ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', $expires_at ),
				'revoked'    => 0,
				'created_at' => gmdate( 'Y-m-d H:i:s', $now ),
				'user_agent' => self::current_user_agent(),
				'ip'         => self::current_ip(),
			],
			[ '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s' ]
		);

		return [
			'raw'        => $raw,
			'jti'        => $jti,
			'expires_at' => $expires_at,
		];
	}

	/**
	 * Find a valid (not revoked, not expired) refresh-token row by raw value.
	 *
	 * @param string $raw Raw token.
	 *
	 * @return object|null Row or null.
	 */
	public static function find_valid( $raw ) {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . self::table() . ' WHERE token_hash = %s LIMIT 1',
				self::hash( $raw )
			)
		);

		if ( ! $row ) {
			return null;
		}

		if ( (int) $row->revoked === 1 ) {
			return null;
		}

		if ( strtotime( $row->expires_at . ' UTC' ) < time() ) {
			return null;
		}

		return $row;
	}

	/**
	 * Look up any row (revoked or not) by raw value. Used to detect reuse of a
	 * rotated/revoked token.
	 *
	 * @param string $raw Raw token.
	 *
	 * @return object|null
	 */
	public static function find_any( $raw ) {
		global $wpdb;

		return $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . self::table() . ' WHERE token_hash = %s LIMIT 1',
				self::hash( $raw )
			)
		);
	}

	/**
	 * Rotate: revoke the old refresh token and issue a fresh one for the user.
	 *
	 * @param string $old_jti Old refresh-token jti.
	 * @param int    $user_id User ID.
	 *
	 * @return array{raw:string,jti:string,expires_at:int} New refresh token.
	 */
	public static function rotate( $old_jti, $user_id ) {
		self::revoke( $old_jti );

		return self::create_refresh_token( $user_id );
	}

	/**
	 * Revoke a single refresh token by jti.
	 *
	 * @param string $jti Refresh-token jti.
	 *
	 * @return void
	 */
	public static function revoke( $jti ) {
		global $wpdb;

		$wpdb->update(
			self::table(),
			[ 'revoked' => 1 ],
			[ 'jti' => $jti ],
			[ '%d' ],
			[ '%s' ]
		);
	}

	/**
	 * Revoke every refresh token for a user (logout-all / compromise response).
	 *
	 * @param int $user_id User ID.
	 *
	 * @return void
	 */
	public static function revoke_all_for_user( $user_id ) {
		global $wpdb;

		$wpdb->update(
			self::table(),
			[ 'revoked' => 1 ],
			[ 'user_id' => (int) $user_id ],
			[ '%d' ],
			[ '%d' ]
		);
	}

	/**
	 * Mark the most recent use of a refresh token.
	 *
	 * @param string $jti Refresh-token jti.
	 *
	 * @return void
	 */
	public static function touch( $jti ) {
		global $wpdb;

		$wpdb->update(
			self::table(),
			[ 'last_used_at' => gmdate( 'Y-m-d H:i:s', time() ) ],
			[ 'jti' => $jti ],
			[ '%s' ],
			[ '%s' ]
		);
	}

	/**
	 * Active (non-revoked, non-expired) sessions for a user.
	 *
	 * @param int $user_id User ID.
	 *
	 * @return array<int,object>
	 */
	public static function sessions_for_user( $user_id ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT jti, created_at, last_used_at, user_agent, ip, expires_at
				 FROM ' . self::table() . '
				 WHERE user_id = %d AND revoked = 0 AND expires_at > %s
				 ORDER BY created_at DESC',
				(int) $user_id,
				gmdate( 'Y-m-d H:i:s', time() )
			)
		);
	}

	/**
	 * Delete expired / long-revoked rows. Cron cleanup.
	 *
	 * @return void
	 */
	public static function purge_expired() {
		global $wpdb;

		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::table() . ' WHERE expires_at < %s',
				gmdate( 'Y-m-d H:i:s', time() )
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * Access-token revocation set (transient-backed, auto-expiring)
	 * ------------------------------------------------------------------- */

	/**
	 * Revoke a specific access-token jti until it would have expired anyway.
	 *
	 * @param string $jti Access-token jti.
	 * @param int    $ttl Seconds remaining on the access token.
	 *
	 * @return void
	 */
	public static function revoke_access_jti( $jti, $ttl ) {
		if ( empty( $jti ) ) {
			return;
		}

		$ttl = max( 1, (int) $ttl );
		set_transient( 'jwt_auth_ext_revoked_' . $jti, 1, $ttl );
	}

	/**
	 * Whether an access-token jti has been revoked.
	 *
	 * @param string $jti Access-token jti.
	 *
	 * @return bool
	 */
	public static function is_access_jti_revoked( $jti ) {
		if ( empty( $jti ) ) {
			return false;
		}

		return (bool) get_transient( 'jwt_auth_ext_revoked_' . $jti );
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------- */

	/**
	 * @return string|null
	 */
	private static function current_ip() {
		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return null;
		}

		return substr( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ), 0, 45 );
	}

	/**
	 * @return string|null
	 */
	private static function current_user_agent() {
		if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return null;
		}

		return substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 );
	}
}
