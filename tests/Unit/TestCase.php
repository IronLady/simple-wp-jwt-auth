<?php
/**
 * Base test case. Ensures the extension table exists for each test.
 */

class TestCase extends WP_UnitTestCase {

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'JWT_AUTH_SECRET_KEY' ) ) {
			define( 'JWT_AUTH_SECRET_KEY', 'test-secret-key-for-phpunit' );
		}

		// Create our refresh-token table in the test DB.
		Ext_Tokens::install_table();
	}

	/**
	 * Whether the base plugin is loaded; integration tests skip if not.
	 */
	protected function basePluginAvailable(): bool {
		return class_exists( 'Jwt_Auth_Public' ) && class_exists( \Tmeister\Firebase\JWT\JWT::class );
	}

	/**
	 * Create a test user.
	 */
	protected function createTestUser( array $args = [] ): WP_User {
		$defaults = [
			'user_login'   => 'testuser_' . wp_generate_password( 6, false ),
			'user_email'   => uniqid( 'u_', true ) . '@example.com',
			'user_pass'    => 'password123',
			'display_name' => 'Test User',
		];

		$user_id = wp_insert_user( array_merge( $defaults, $args ) );
		if ( is_wp_error( $user_id ) ) {
			$this->fail( 'Failed to create test user: ' . $user_id->get_error_message() );
		}

		return get_user_by( 'id', $user_id );
	}

	/**
	 * Build a signed access token with the given claims (uses base Firebase lib).
	 */
	protected function makeAccessToken( WP_User $user, array $overrides = [] ): string {
		$issued_at = time();
		$payload   = array_merge( [
			'iss'  => get_bloginfo( 'url' ),
			'iat'  => $issued_at,
			'nbf'  => $issued_at,
			'exp'  => $issued_at + 900,
			'jti'  => wp_generate_uuid4(),
			'typ'  => 'access',
			'data' => [ 'user' => [ 'id' => $user->ID ] ],
		], $overrides );

		return \Tmeister\Firebase\JWT\JWT::encode( $payload, JWT_AUTH_SECRET_KEY, 'HS256' );
	}
}
