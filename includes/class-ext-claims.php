<?php
/**
 * Shapes the access token the base plugin issues, and attaches a refresh token
 * to the login response. Pure filter hooks — the base plugin is never edited.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Claims {

	/** Default access-token lifetime: 15 minutes. */
	const DEFAULT_ACCESS_TTL = 900;

	/**
	 * Register filters on the base plugin.
	 *
	 * @return void
	 */
	public function register() {
		add_filter( 'jwt_auth_expire', [ $this, 'access_expiry' ], 10, 2 );
		add_filter( 'jwt_auth_token_before_sign', [ $this, 'add_claims' ], 10, 2 );
		add_filter( 'jwt_auth_token_before_dispatch', [ $this, 'attach_refresh_token' ], 10, 2 );
	}

	/**
	 * Access-token lifetime in seconds (filterable / option-configurable).
	 *
	 * @return int
	 */
	public static function access_ttl() {
		$ttl = (int) get_option( 'jwt_auth_ext_access_ttl', self::DEFAULT_ACCESS_TTL );
		if ( $ttl <= 0 ) {
			$ttl = self::DEFAULT_ACCESS_TTL;
		}

		return (int) apply_filters( 'jwt_auth_ext_access_ttl', $ttl );
	}

	/**
	 * Shorten the access token from the base plugin's 7-day default.
	 *
	 * @param int $expire    Original expiry (unused; we recompute from issuedAt).
	 * @param int $issued_at Issued-at timestamp.
	 *
	 * @return int
	 */
	public function access_expiry( $expire, $issued_at ) {
		return (int) $issued_at + self::access_ttl();
	}

	/**
	 * Add `jti` and `typ` claims so individual access tokens can be tracked
	 * and refresh tokens can't be replayed as access tokens.
	 *
	 * @param array   $payload Token payload before signing.
	 * @param WP_User $user    Authenticated user.
	 *
	 * @return array
	 */
	public function add_claims( $payload, $user ) {
		if ( empty( $payload['jti'] ) ) {
			$payload['jti'] = wp_generate_uuid4();
		}
		$payload['typ'] = 'access';

		return $payload;
	}

	/**
	 * Mint a refresh token for the user and append it to the login response.
	 *
	 * @param array   $data Response payload.
	 * @param WP_User $user Authenticated user.
	 *
	 * @return array
	 */
	public function attach_refresh_token( $data, $user ) {
		if ( ! $user instanceof WP_User && isset( $user->data->ID ) ) {
			$user_id = (int) $user->data->ID;
		} else {
			$user_id = (int) $user->ID;
		}

		if ( ! $user_id ) {
			return $data;
		}

		$refresh = Ext_Tokens::create_refresh_token( $user_id );

		$data['refresh_token']      = $refresh['raw'];
		$data['refresh_expires_in'] = Ext_Tokens::ttl();
		$data['expires_in']         = self::access_ttl();
		$data['token_type']         = 'Bearer';

		return $data;
	}
}
