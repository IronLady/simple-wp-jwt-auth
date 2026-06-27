<?php
/**
 * New REST endpoints: token refresh (with rotation), revoke (logout), sessions.
 *
 * Registered under the base plugin's namespace so they sit beside /token.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Routes {

	/** REST namespace — matches the base plugin (jwt-auth/v1). */
	const NS = 'jwt-auth/v1';

	/**
	 * Hook route registration.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'rest_api_init', [ $this, 'add_routes' ] );
	}

	/**
	 * @return void
	 */
	public function add_routes() {
		register_rest_route( self::NS, 'token/refresh', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'refresh' ],
			'permission_callback' => '__return_true',
		] );

		register_rest_route( self::NS, 'token/revoke', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'revoke' ],
			'permission_callback' => '__return_true',
		] );

		register_rest_route( self::NS, 'sessions', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'sessions' ],
			'permission_callback' => [ $this, 'require_logged_in' ],
		] );
	}

	/**
	 * Exchange a valid refresh token for a new access + refresh pair (rotation).
	 *
	 * @param WP_REST_Request $request Request.
	 *
	 * @return array|WP_Error
	 */
	public function refresh( WP_REST_Request $request ) {
		if ( ! Ext_Jwt::available() ) {
			return new WP_Error( 'jwt_auth_bad_config', 'JWT is not configured properly.', [ 'status' => 403 ] );
		}

		$raw = $request->get_param( 'refresh_token' );
		if ( empty( $raw ) ) {
			return new WP_Error( 'jwt_auth_ext_no_refresh_token', 'refresh_token is required.', [ 'status' => 400 ] );
		}

		$row = Ext_Tokens::find_valid( $raw );

		if ( ! $row ) {
			/*
			 * Token unknown, expired, OR revoked. If it matches a row that was
			 * already revoked, this is a reuse of a rotated token — treat as a
			 * compromise and kill every session for that user.
			 */
			$any = Ext_Tokens::find_any( $raw );
			if ( $any && (int) $any->revoked === 1 ) {
				Ext_Tokens::revoke_all_for_user( $any->user_id );
			}

			return new WP_Error( 'jwt_auth_ext_invalid_refresh_token', 'Refresh token is invalid, expired, or revoked.', [ 'status' => 401 ] );
		}

		$user = get_user_by( 'id', (int) $row->user_id );
		if ( ! $user ) {
			Ext_Tokens::revoke( $row->jti );

			return new WP_Error( 'jwt_auth_ext_invalid_user', 'User no longer exists.', [ 'status' => 401 ] );
		}

		// Rotate the refresh token.
		$new_refresh = Ext_Tokens::rotate( $row->jti, (int) $row->user_id );

		// Mint a new access token using the base plugin's claim/expiry filters.
		$access = $this->mint_access_token( $user );
		if ( is_wp_error( $access ) ) {
			return $access;
		}

		$data = [
			'token'              => $access,
			'user_email'         => $user->user_email,
			'user_nicename'      => $user->user_nicename,
			'user_display_name'  => $user->display_name,
			'refresh_token'      => $new_refresh['raw'],
			'refresh_expires_in' => Ext_Tokens::ttl(),
			'expires_in'         => Ext_Claims::access_ttl(),
			'token_type'         => 'Bearer',
		];

		return apply_filters( 'jwt_auth_ext_refresh_before_dispatch', $data, $user );
	}

	/**
	 * Logout: revoke the current access token immediately, and optionally the
	 * presented refresh token or every session.
	 *
	 * @param WP_REST_Request $request Request.
	 *
	 * @return array|WP_Error
	 */
	public function revoke( WP_REST_Request $request ) {
		$payload = $this->current_access_payload();
		if ( ! $payload ) {
			return new WP_Error( 'jwt_auth_ext_no_access_token', 'A valid access token is required.', [ 'status' => 401 ] );
		}

		$user_id = isset( $payload->data->user->id ) ? (int) $payload->data->user->id : 0;

		// Immediately blacklist this access token for its remaining lifetime.
		if ( ! empty( $payload->jti ) ) {
			$ttl = isset( $payload->exp ) ? ( (int) $payload->exp - time() ) : Ext_Claims::access_ttl();
			Ext_Tokens::revoke_access_jti( $payload->jti, $ttl );
		}

		$all = filter_var( $request->get_param( 'all' ), FILTER_VALIDATE_BOOLEAN );
		if ( $all && $user_id ) {
			Ext_Tokens::revoke_all_for_user( $user_id );

			return [ 'code' => 'jwt_auth_ext_revoked_all', 'data' => [ 'status' => 200 ] ];
		}

		// Revoke the specific refresh token if the client sent it.
		$raw = $request->get_param( 'refresh_token' );
		if ( ! empty( $raw ) ) {
			$row = Ext_Tokens::find_any( $raw );
			if ( $row && ( ! $user_id || (int) $row->user_id === $user_id ) ) {
				Ext_Tokens::revoke( $row->jti );
			}
		}

		return [ 'code' => 'jwt_auth_ext_revoked', 'data' => [ 'status' => 200 ] ];
	}

	/**
	 * List the current user's active sessions.
	 *
	 * @return array
	 */
	public function sessions() {
		$rows = Ext_Tokens::sessions_for_user( get_current_user_id() );

		return [ 'sessions' => $rows ];
	}

	/**
	 * Permission callback for the sessions endpoint.
	 *
	 * @return bool
	 */
	public function require_logged_in() {
		return is_user_logged_in();
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Sign a fresh access token for a user, going through the base plugin's
	 * filters (jwt_auth_token_before_sign / jwt_auth_expire / jwt_auth_algorithm)
	 * so it is identical to a /token-issued token.
	 *
	 * @param WP_User $user User.
	 *
	 * @return string|WP_Error
	 */
	private function mint_access_token( $user ) {
		$issued_at  = time();
		$not_before = apply_filters( 'jwt_auth_not_before', $issued_at, $issued_at );
		$expire     = apply_filters( 'jwt_auth_expire', $issued_at + ( DAY_IN_SECONDS * 7 ), $issued_at );

		$payload = [
			'iss'  => get_bloginfo( 'url' ),
			'iat'  => $issued_at,
			'nbf'  => $not_before,
			'exp'  => $expire,
			'data' => [
				'user' => [
					'id' => $user->ID,
				],
			],
		];

		$payload = apply_filters( 'jwt_auth_token_before_sign', $payload, $user );

		try {
			return \Tmeister\Firebase\JWT\JWT::encode( $payload, Ext_Jwt::secret(), Ext_Jwt::algorithm() );
		} catch ( Exception $e ) {
			return new WP_Error( 'jwt_auth_ext_sign_failed', $e->getMessage(), [ 'status' => 500 ] );
		}
	}

	/**
	 * Decode the access token on the current request, if any.
	 *
	 * @return object|null
	 */
	private function current_access_payload() {
		$token = Ext_Jwt::bearer_from_header( Ext_Jwt::request_auth_header() );

		return $token ? Ext_Jwt::decode( $token ) : null;
	}
}
