<?php
/**
 * Tests for the WP Secrets public API.
 *
 * Covers the WP_Secrets static facade, global helper functions,
 * key validation, hook integration, and provider resolution.
 *
 * @package WP_Secrets_Manager
 * @group   api
 */

class Secrets_API_Test extends WP_UnitTestCase {

	/**
	 * Context array used across most tests to bypass access control.
	 *
	 * @var array
	 */
	private $cli_context = array( 'is_cli' => true );

	/**
	 * Keys created during a test, cleaned up in tearDown.
	 *
	 * @var string[]
	 */
	private $test_keys = array();

	/**
	 * Filter callbacks registered during a test, removed in tearDown.
	 *
	 * @var array[] Each entry: [ hook, callback, priority ].
	 */
	private $registered_filters = array();

	/**
	 * Set up a fresh manager instance before every test.
	 */
	public function setUp(): void {
		parent::setUp();

		WP_Secrets_Manager::reset();

		$manager = WP_Secrets_Manager::get_instance();
		$manager->register_provider( new Provider_Encrypted_Options() );
		$manager->select_provider();
	}

	/**
	 * Clean up secrets and filters after every test.
	 */
	public function tearDown(): void {
		foreach ( $this->test_keys as $key ) {
			$option = Provider_Encrypted_Options::option_name( $key );
			delete_option( $option );
		}

		foreach ( $this->registered_filters as $entry ) {
			remove_filter( $entry[0], $entry[1], $entry[2] );
		}

		$this->test_keys          = array();
		$this->registered_filters = array();

		WP_Secrets_Manager::reset();

		parent::tearDown();
	}

	/**
	 * Track a key for automatic cleanup.
	 *
	 * @param string $key Secret key.
	 */
	private function track_key( string $key ): void {
		$this->test_keys[] = $key;
	}

	/**
	 * Register a filter and track it for automatic removal.
	 *
	 * @param string   $hook     Filter hook name.
	 * @param callable $callback Callback.
	 * @param int      $priority Priority.
	 */
	private function add_tracked_filter( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): void {
		add_filter( $hook, $callback, $priority, $accepted_args );
		$this->registered_filters[] = array( $hook, $callback, $priority );
	}

	// ------------------------------------------------------------------
	// 1–6. Basic CRUD via WP_Secrets facade
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_get_returns_null_for_nonexistent_key() {
		$result = WP_Secrets::get( 'test-plugin/nonexistent', $this->cli_context );

		$this->assertNull( $result );
	}

	/**
	 * @group api
	 */
	public function test_set_then_get_returns_value() {
		$key   = 'test-plugin/api_key';
		$value = 'sk_live_abc123';

		$this->track_key( $key );

		$set_result = WP_Secrets::set( $key, $value, $this->cli_context );
		$got        = WP_Secrets::get( $key, $this->cli_context );

		$this->assertTrue( $set_result );
		$this->assertSame( $value, $got );
	}

	/**
	 * @group api
	 */
	public function test_delete_returns_true_for_existing() {
		$key = 'test-plugin/to_delete';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'temporary', $this->cli_context );
		$result = WP_Secrets::delete( $key, $this->cli_context );

		$this->assertTrue( $result );
	}

	/**
	 * @group api
	 */
	public function test_delete_returns_false_for_nonexistent() {
		$result = WP_Secrets::delete( 'test-plugin/never_existed', $this->cli_context );

		$this->assertFalse( $result );
	}

	/**
	 * @group api
	 */
	public function test_exists_returns_true_after_set() {
		$key = 'test-plugin/check_exists';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'present', $this->cli_context );

		$this->assertTrue( WP_Secrets::exists( $key, $this->cli_context ) );
	}

	/**
	 * @group api
	 */
	public function test_exists_returns_false_for_nonexistent() {
		$this->assertFalse( WP_Secrets::exists( 'test-plugin/ghost', $this->cli_context ) );
	}

	// ------------------------------------------------------------------
	// 7. list_keys
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_list_keys_returns_matching() {
		$keys = array(
			'myapp/key_one',
			'myapp/key_two',
			'other/unrelated',
		);

		foreach ( $keys as $key ) {
			$this->track_key( $key );
			WP_Secrets::set( $key, 'val', $this->cli_context );
		}

		$listed = WP_Secrets::list_keys( 'myapp/', $this->cli_context );

		$this->assertContains( 'myapp/key_one', $listed );
		$this->assertContains( 'myapp/key_two', $listed );
		$this->assertNotContains( 'other/unrelated', $listed );
	}

	// ------------------------------------------------------------------
	// 8–11. Global helper functions match static facade
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_helper_get_secret_matches_static() {
		$key = 'test-plugin/helper_get';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'via_static', $this->cli_context );

		$this->assertSame(
			WP_Secrets::get( $key, $this->cli_context ),
			get_secret( $key, $this->cli_context )
		);
	}

	/**
	 * @group api
	 */
	public function test_helper_set_secret_matches_static() {
		$key = 'test-plugin/helper_set';
		$this->track_key( $key );

		$result = set_secret( $key, 'helper_value', $this->cli_context );

		$this->assertTrue( $result );
		$this->assertSame( 'helper_value', WP_Secrets::get( $key, $this->cli_context ) );
	}

	/**
	 * @group api
	 */
	public function test_helper_delete_secret_matches_static() {
		$key = 'test-plugin/helper_del';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'doomed', $this->cli_context );

		$this->assertTrue( delete_secret( $key, $this->cli_context ) );
		$this->assertNull( WP_Secrets::get( $key, $this->cli_context ) );
	}

	/**
	 * @group api
	 */
	public function test_helper_secret_exists_matches_static() {
		$key = 'test-plugin/helper_exists';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'here', $this->cli_context );

		$this->assertSame(
			WP_Secrets::exists( $key, $this->cli_context ),
			secret_exists( $key, $this->cli_context )
		);
	}

	// ------------------------------------------------------------------
	// 12–16. Key validation
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_key_without_namespace_rejected() {
		$result = set_secret( 'nonamespace', 'val', $this->cli_context );

		$this->assertFalse( $result );
	}

	/**
	 * @group api
	 */
	public function test_key_with_namespace_accepted() {
		$key = 'valid-plugin/api_key';
		$this->track_key( $key );

		$result = set_secret( $key, 'accepted', $this->cli_context );

		$this->assertTrue( $result );
	}

	/**
	 * @group api
	 */
	public function test_empty_key_rejected() {
		$result = set_secret( '', 'val', $this->cli_context );

		$this->assertFalse( $result );
	}

	/**
	 * @group api
	 */
	public function test_invalid_characters_rejected() {
		$invalid_keys = array(
			'my plugin/has spaces',
			'my-plugin/key@value',
			'my-plugin/key#hash',
			'my-plugin/key$dollar',
			'my-plugin/key!bang',
		);

		foreach ( $invalid_keys as $key ) {
			$this->assertFalse(
				set_secret( $key, 'val', $this->cli_context ),
				"Expected key '{$key}' to be rejected"
			);
		}
	}

	/**
	 * @group api
	 */
	public function test_global_flag_allows_unnamespaced_key() {
		$key     = 'global_infrastructure_key';
		$context = array_merge( $this->cli_context, array( 'global' => true ) );

		$this->track_key( $key );

		$result = set_secret( $key, 'global_value', $context );

		$this->assertTrue( $result );
		$this->assertSame( 'global_value', get_secret( $key, $context ) );
	}

	// ------------------------------------------------------------------
	// 17–18. Pre-operation filters
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_pre_get_filter_can_short_circuit() {
		$key = 'test-plugin/pre_get';

		$this->add_tracked_filter(
			'wp_secrets_pre_get',
			function ( $value, $filter_key ) use ( $key ) {
				if ( $key === $filter_key ) {
					return 'short_circuited_value';
				}
				return $value;
			},
			10,
			3
		);

		$result = WP_Secrets::get( $key, $this->cli_context );

		$this->assertSame( 'short_circuited_value', $result );
	}

	/**
	 * @group api
	 */
	public function test_pre_set_filter_can_modify_value() {
		$key = 'test-plugin/pre_set';
		$this->track_key( $key );

		$this->add_tracked_filter(
			'wp_secrets_pre_set',
			function ( $value, $filter_key ) use ( $key ) {
				if ( $key === $filter_key ) {
					return 'modified_' . $value;
				}
				return $value;
			},
			10,
			3
		);

		WP_Secrets::set( $key, 'original', $this->cli_context );
		$stored = WP_Secrets::get( $key, $this->cli_context );

		$this->assertSame( 'modified_original', $stored );
	}

	// ------------------------------------------------------------------
	// 19–20. Post-operation actions
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_post_set_action_fires() {
		$key = 'test-plugin/post_set';
		$this->track_key( $key );

		$before = did_action( 'wp_secrets_post_set' );

		WP_Secrets::set( $key, 'value', $this->cli_context );

		$this->assertSame( $before + 1, did_action( 'wp_secrets_post_set' ) );
	}

	/**
	 * @group api
	 */
	public function test_post_delete_action_fires() {
		$key = 'test-plugin/post_del';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'value', $this->cli_context );

		$before = did_action( 'wp_secrets_post_delete' );

		WP_Secrets::delete( $key, $this->cli_context );

		$this->assertSame( $before + 1, did_action( 'wp_secrets_post_delete' ) );
	}

	// ------------------------------------------------------------------
	// 21–22. Audit accessed action
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_accessed_action_fires_on_get() {
		$key = 'test-plugin/audit_get';
		$this->track_key( $key );

		WP_Secrets::set( $key, 'val', $this->cli_context );

		$before = did_action( 'wp_secrets_accessed' );

		WP_Secrets::get( $key, $this->cli_context );

		$this->assertGreaterThan( $before, did_action( 'wp_secrets_accessed' ) );
	}

	/**
	 * @group api
	 */
	public function test_accessed_action_fires_on_set() {
		$key = 'test-plugin/audit_set';
		$this->track_key( $key );

		$before = did_action( 'wp_secrets_accessed' );

		WP_Secrets::set( $key, 'val', $this->cli_context );

		$this->assertGreaterThan( $before, did_action( 'wp_secrets_accessed' ) );
	}

	// ------------------------------------------------------------------
	// 23. Provider filter override
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_provider_filter_can_override() {
		$mock_provider = $this->createMock( WP_Secrets_Provider::class );
		$mock_provider->method( 'get_id' )->willReturn( 'mock-provider' );
		$mock_provider->method( 'get_name' )->willReturn( 'Mock Provider' );
		$mock_provider->method( 'get_priority' )->willReturn( 1 );
		$mock_provider->method( 'is_available' )->willReturn( true );
		$mock_provider->method( 'get' )->willReturn( 'from_mock' );
		$mock_provider->method( 'set' )->willReturn( true );
		$mock_provider->method( 'exists' )->willReturn( true );
		$mock_provider->method( 'list_keys' )->willReturn( array() );
		$mock_provider->method( 'health_check' )->willReturn(
			array(
				'status'  => 'good',
				'message' => 'Mock OK',
			)
		);

		$manager = WP_Secrets_Manager::get_instance();
		$manager->register_provider( $mock_provider );

		$key = 'routed/secret';

		$this->add_tracked_filter(
			'wp_secrets_provider',
			function ( $provider_id, $filter_key ) use ( $key ) {
				if ( $key === $filter_key ) {
					return 'mock-provider';
				}
				return $provider_id;
			},
			10,
			3
		);

		$result = WP_Secrets::get( $key, $this->cli_context );

		$this->assertSame( 'from_mock', $result );
	}

	// ------------------------------------------------------------------
	// 24. No provider available
	// ------------------------------------------------------------------

	/**
	 * @group api
	 */
	public function test_returns_null_when_no_provider() {
		WP_Secrets_Manager::reset();

		$result = WP_Secrets::get( 'orphan/key', $this->cli_context );

		$this->assertNull( $result );
	}
}
