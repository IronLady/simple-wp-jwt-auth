<?php
/**
 * Per-IP rate limiting for the credential-bearing endpoints (token + refresh).
 *
 * Transient-backed sliding-ish window. Short-circuits via rest_pre_dispatch
 * with HTTP 429 before the base plugin's /token callback runs.
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

class Ext_Rate_Limit {

	/** Max attempts per window. */
	const MAX_ATTEMPTS = 5;

	/** Window length in seconds. */
	const WINDOW = 300;

	/** Routes that are throttled (suffix match on the REST route). */
	const ROUTES = [ '/jwt-auth/v1/token', '/jwt-auth/v1/token/refresh' ];

	/**
	 * @return void
	 */
	public function register() {
		add_filter( 'rest_pre_dispatch', [ $this, 'enforce' ], 4, 3 );
	}

	/**
	 * @param mixed           $result  Existing short-circuit result.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Current request.
	 *
	 * @return mixed|WP_Error
	 */
	public function enforce( $result, $server, $request ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		$route = $request->get_route();
		if ( ! in_array( $route, self::ROUTES, true ) ) {
			return $result;
		}

		$max    = (int) apply_filters( 'jwt_auth_ext_rate_limit_max', self::MAX_ATTEMPTS, $route );
		$window = (int) apply_filters( 'jwt_auth_ext_rate_limit_window', self::WINDOW, $route );

		$key   = 'jwt_auth_ext_rl_' . md5( $route . '|' . $this->client_ip() );
		$count = (int) get_transient( $key );
		$count++;

		set_transient( $key, $count, $window );

		$remaining = max( 0, $max - $count );
		$this->maybe_send_headers( $max, $remaining, $window );

		if ( $count > $max ) {
			return new WP_Error(
				'jwt_auth_too_many_attempts',
				'Too many attempts. Please try again later.',
				[ 'status' => 429 ]
			);
		}

		return $result;
	}

	/**
	 * Emit X-RateLimit-* headers unless disabled via the base plugin's filter.
	 *
	 * @param int $max       Limit.
	 * @param int $remaining Remaining attempts.
	 * @param int $window    Window seconds.
	 *
	 * @return void
	 */
	private function maybe_send_headers( $max, $remaining, $window ) {
		if ( ! apply_filters( 'jwt_auth_rate_limit_headers_enabled', true ) ) {
			return;
		}
		if ( headers_sent() ) {
			return;
		}

		header( 'X-RateLimit-Limit: ' . $max );
		header( 'X-RateLimit-Remaining: ' . $remaining );
		header( 'X-RateLimit-Reset: ' . ( time() + $window ) );
	}

	/**
	 * @return string
	 */
	private function client_ip() {
		return ! empty( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '0.0.0.0';
	}
}
