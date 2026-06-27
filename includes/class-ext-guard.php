<?php
/**
 * Enforces token type + revocation on incoming REST requests.
 *
 * The base plugin authenticates via determine_current_user but has no notion of
 * revocation or token type. We hook rest_pre_dispatch BEFORE the base plugin
 * (priority 5 < base's 10) and reject:
 *   - refresh / non-"access" tokens replayed as bearer credentials
 *   - access tokens whose jti has been revoked (immediate logout)
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Guard {

	/**
	 * @return void
	 */
	public function register() {
		add_filter( 'rest_pre_dispatch', [ $this, 'enforce' ], 5, 3 );
	}

	/**
	 * @param mixed           $result  Existing short-circuit result.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Current request.
	 *
	 * @return mixed|WP_Error
	 */
	public function enforce( $result, $server, $request ) {
		// Respect an already-set short-circuit.
		if ( ! empty( $result ) ) {
			return $result;
		}

		$token = Ext_Jwt::bearer_from_header( Ext_Jwt::request_auth_header() );
		if ( ! $token ) {
			return $result;
		}

		$payload = Ext_Jwt::decode( $token );
		if ( ! $payload ) {
			// Not a decodable JWT (e.g. opaque value) — let the base plugin decide.
			return $result;
		}

		// Block anything that isn't an access token. Tokens issued before this
		// plugin (no typ claim) are treated as access for backwards-compat.
		if ( isset( $payload->typ ) && $payload->typ !== 'access' ) {
			return new WP_Error(
				'jwt_auth_ext_wrong_token_type',
				'This token type cannot be used to authenticate requests.',
				[ 'status' => 401 ]
			);
		}

		// Block revoked access tokens.
		if ( ! empty( $payload->jti ) && Ext_Tokens::is_access_jti_revoked( $payload->jti ) ) {
			return new WP_Error(
				'jwt_auth_ext_revoked_token',
				'This token has been revoked.',
				[ 'status' => 401 ]
			);
		}

		return $result;
	}
}
