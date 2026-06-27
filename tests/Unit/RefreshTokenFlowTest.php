<?php
/**
 * Integration tests for the refresh-token / revocation / rate-limit flows.
 */

class RefreshTokenFlowTest extends TestCase {

	private function skipIfNoBase(): void {
		if ( ! $this->basePluginAvailable() ) {
			$this->markTestSkipped( 'Base JWT plugin not available.' );
		}
	}

	/* ---------------- repository ---------------- */

	public function test_create_refresh_token_persists_hash_not_raw() {
		global $wpdb;
		$user = $this->createTestUser();

		$rt = Ext_Tokens::create_refresh_token( $user->ID );

		$this->assertNotEmpty( $rt['raw'] );
		$this->assertSame( 64, strlen( $rt['raw'] ) ); // 32 bytes hex

		$stored = $wpdb->get_var( $wpdb->prepare(
			'SELECT token_hash FROM ' . Ext_Tokens::table() . ' WHERE jti = %s',
			$rt['jti']
		) );

		$this->assertSame( hash( 'sha256', $rt['raw'] ), $stored );
		$this->assertNotSame( $rt['raw'], $stored, 'Raw token must never be stored.' );
	}

	public function test_find_valid_matches_then_rejects_after_revoke() {
		$user = $this->createTestUser();
		$rt   = Ext_Tokens::create_refresh_token( $user->ID );

		$this->assertNotNull( Ext_Tokens::find_valid( $rt['raw'] ) );

		Ext_Tokens::revoke( $rt['jti'] );
		$this->assertNull( Ext_Tokens::find_valid( $rt['raw'] ) );
	}

	public function test_rotation_invalidates_old_token() {
		$user = $this->createTestUser();
		$rt   = Ext_Tokens::create_refresh_token( $user->ID );

		$new = Ext_Tokens::rotate( $rt['jti'], $user->ID );

		$this->assertNull( Ext_Tokens::find_valid( $rt['raw'] ), 'Old token must die after rotation.' );
		$this->assertNotNull( Ext_Tokens::find_valid( $new['raw'] ) );
	}

	public function test_revoke_all_for_user() {
		$user = $this->createTestUser();
		$a    = Ext_Tokens::create_refresh_token( $user->ID );
		$b    = Ext_Tokens::create_refresh_token( $user->ID );

		Ext_Tokens::revoke_all_for_user( $user->ID );

		$this->assertNull( Ext_Tokens::find_valid( $a['raw'] ) );
		$this->assertNull( Ext_Tokens::find_valid( $b['raw'] ) );
	}

	public function test_access_jti_revocation_set() {
		$jti = wp_generate_uuid4();
		$this->assertFalse( Ext_Tokens::is_access_jti_revoked( $jti ) );

		Ext_Tokens::revoke_access_jti( $jti, 300 );
		$this->assertTrue( Ext_Tokens::is_access_jti_revoked( $jti ) );
	}

	/* ---------------- claims ---------------- */

	public function test_claims_shorten_expiry_and_add_type() {
		$claims = new Ext_Claims();

		$expiry = $claims->access_expiry( time() + DAY_IN_SECONDS * 7, time() );
		$this->assertLessThanOrEqual( time() + Ext_Claims::access_ttl() + 1, $expiry );

		$user    = $this->createTestUser();
		$payload = $claims->add_claims( [ 'data' => [] ], $user );
		$this->assertSame( 'access', $payload['typ'] );
		$this->assertNotEmpty( $payload['jti'] );
	}

	public function test_login_response_gets_refresh_token() {
		$user = $this->createTestUser();
		$data = ( new Ext_Claims() )->attach_refresh_token( [ 'token' => 'x' ], $user );

		$this->assertArrayHasKey( 'refresh_token', $data );
		$this->assertSame( Ext_Claims::access_ttl(), $data['expires_in'] );
		$this->assertSame( 'Bearer', $data['token_type'] );
		$this->assertNotNull( Ext_Tokens::find_valid( $data['refresh_token'] ) );
	}

	/* ---------------- routes ---------------- */

	public function test_refresh_endpoint_rotates_and_returns_new_pair() {
		$this->skipIfNoBase();
		$user = $this->createTestUser();
		$rt   = Ext_Tokens::create_refresh_token( $user->ID );

		$req = new WP_REST_Request( 'POST', '/jwt-auth/v1/token/refresh' );
		$req->set_param( 'refresh_token', $rt['raw'] );

		$res = ( new Ext_Routes() )->refresh( $req );

		$this->assertIsArray( $res );
		$this->assertNotEmpty( $res['token'] );
		$this->assertNotEmpty( $res['refresh_token'] );
		$this->assertNotSame( $rt['raw'], $res['refresh_token'] );
		$this->assertNull( Ext_Tokens::find_valid( $rt['raw'] ), 'Old refresh token must be revoked.' );
	}

	public function test_reused_rotated_token_kills_all_sessions() {
		$this->skipIfNoBase();
		$user  = $this->createTestUser();
		$rt    = Ext_Tokens::create_refresh_token( $user->ID );
		$other = Ext_Tokens::create_refresh_token( $user->ID );

		$routes = new Ext_Routes();
		$req    = new WP_REST_Request( 'POST', '/jwt-auth/v1/token/refresh' );
		$req->set_param( 'refresh_token', $rt['raw'] );

		// First use rotates fine.
		$routes->refresh( $req );

		// Replay the now-revoked token -> compromise response.
		$replay = $routes->refresh( $req );
		$this->assertInstanceOf( WP_Error::class, $replay );
		$this->assertSame( 'jwt_auth_ext_invalid_refresh_token', $replay->get_error_code() );

		// Every other session for the user is now dead.
		$this->assertNull( Ext_Tokens::find_valid( $other['raw'] ) );
	}

	public function test_revoke_endpoint_blacklists_access_jti() {
		$this->skipIfNoBase();
		$user  = $this->createTestUser();
		$token = $this->makeAccessToken( $user );
		$jti   = Ext_Jwt::decode( $token )->jti;

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

		$res = ( new Ext_Routes() )->revoke( new WP_REST_Request( 'POST', '/jwt-auth/v1/token/revoke' ) );

		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$this->assertIsArray( $res );
		$this->assertTrue( Ext_Tokens::is_access_jti_revoked( $jti ) );
	}

	/* ---------------- guard ---------------- */

	public function test_guard_rejects_revoked_access_token() {
		$this->skipIfNoBase();
		$user  = $this->createTestUser();
		$token = $this->makeAccessToken( $user );
		$jti   = Ext_Jwt::decode( $token )->jti;
		Ext_Tokens::revoke_access_jti( $jti, 300 );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
		$result = ( new Ext_Guard() )->enforce( null, null, new WP_REST_Request() );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwt_auth_ext_revoked_token', $result->get_error_code() );
	}

	public function test_guard_rejects_non_access_token_type() {
		$this->skipIfNoBase();
		$user  = $this->createTestUser();
		$token = $this->makeAccessToken( $user, [ 'typ' => 'refresh' ] );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
		$result = ( new Ext_Guard() )->enforce( null, null, new WP_REST_Request() );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'jwt_auth_ext_wrong_token_type', $result->get_error_code() );
	}

	public function test_guard_passes_valid_access_token() {
		$this->skipIfNoBase();
		$user  = $this->createTestUser();
		$token = $this->makeAccessToken( $user );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
		$result = ( new Ext_Guard() )->enforce( null, null, new WP_REST_Request() );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$this->assertNull( $result );
	}

	/* ---------------- rate limit ---------------- */

	public function test_rate_limit_blocks_after_max_attempts() {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$rl  = new Ext_Rate_Limit();
		$req = new WP_REST_Request( 'POST', '/jwt-auth/v1/token' );
		$req->set_route( '/jwt-auth/v1/token' );

		$last = null;
		for ( $i = 0; $i < Ext_Rate_Limit::MAX_ATTEMPTS + 1; $i++ ) {
			$last = $rl->enforce( null, null, $req );
		}

		$this->assertInstanceOf( WP_Error::class, $last );
		$this->assertSame( 'jwt_auth_too_many_attempts', $last->get_error_code() );
	}

	public function test_rate_limit_ignores_other_routes() {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
		$req = new WP_REST_Request( 'GET', '/wp/v2/posts' );
		$req->set_route( '/wp/v2/posts' );

		$result = ( new Ext_Rate_Limit() )->enforce( null, null, $req );
		$this->assertNull( $result );
	}
}
