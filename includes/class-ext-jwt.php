<?php
/**
 * Thin helper around the base plugin's bundled Firebase JWT library.
 *
 * Reuses Tmeister\Firebase\JWT (loaded by the base plugin) and the same
 * secret/algorithm, so tokens stay byte-compatible with what the base plugin
 * issues and validates.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

use Tmeister\Firebase\JWT\JWT;
use Tmeister\Firebase\JWT\Key;

class Ext_Jwt {

	/**
	 * Secret key from wp-config.php, or false if missing.
	 *
	 * @return string|false
	 */
	public static function secret() {
		return defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
	}

	/**
	 * Signing algorithm — same filter the base plugin honors.
	 *
	 * @return string
	 */
	public static function algorithm() {
		return apply_filters( 'jwt_auth_algorithm', 'HS256' );
	}

	/**
	 * Whether the base plugin's JWT classes are available.
	 *
	 * @return bool
	 */
	public static function available() {
		return class_exists( JWT::class ) && self::secret() !== false;
	}

	/**
	 * Extract the raw bearer token from an Authorization header value.
	 *
	 * @param string|false $header Header value.
	 *
	 * @return string|null
	 */
	public static function bearer_from_header( $header ) {
		if ( ! $header || strpos( $header, 'Bearer' ) !== 0 ) {
			return null;
		}
		[ $token ] = sscanf( $header, 'Bearer %s' );

		return $token ?: null;
	}

	/**
	 * Read the Authorization header from the current request.
	 *
	 * @return string|false
	 */
	public static function request_auth_header() {
		if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		}
		if ( ! empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) );
		}

		return false;
	}

	/**
	 * Decode a JWT. Returns the decoded payload object or null on any failure.
	 *
	 * @param string $token Raw JWT string.
	 *
	 * @return object|null
	 */
	public static function decode( $token ) {
		if ( ! self::available() || empty( $token ) ) {
			return null;
		}

		try {
			return JWT::decode( $token, new Key( self::secret(), self::algorithm() ) );
		} catch ( Exception $e ) {
			return null;
		}
	}
}
