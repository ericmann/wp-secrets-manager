<?php
/**
 * Tests for the Provider_Encrypted_Options class.
 *
 * @package WP_Secrets_Manager
 * @group   encrypted
 */

class Test_Provider_Encrypted extends WP_UnitTestCase {

	/**
	 * Provider instance under test.
	 *
	 * @var Provider_Encrypted_Options
	 */
	private $provider;

	/**
	 * Set up each test.
	 */
	public function setUp(): void {
		parent::setUp();

		$this->provider = new Provider_Encrypted_Options();
		$this->provider->reset_cache();

		$this->clean_secrets_options();
	}

	/**
	 * Tear down each test.
	 */
	public function tearDown(): void {
		$this->clean_secrets_options();

		parent::tearDown();
	}

	/**
	 * Remove all secret-related options from the database.
	 */
	private function clean_secrets_options(): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name = %s",
				$wpdb->esc_like( '_wp_secret_' ) . '%',
				'_wp_secrets_master_key'
			)
		);

		wp_cache_flush();
	}

	/**
	 * @covers Provider_Encrypted_Options::get_id
	 */
	public function test_get_id() {
		$this->assertSame( 'encrypted-options', $this->provider->get_id() );
	}

	/**
	 * @covers Provider_Encrypted_Options::get_name
	 */
	public function test_get_name() {
		$name = $this->provider->get_name();

		$this->assertIsString( $name );
		$this->assertNotEmpty( $name );
	}

	/**
	 * @covers Provider_Encrypted_Options::get_priority
	 */
	public function test_get_priority() {
		$this->assertSame( 50, $this->provider->get_priority() );
	}

	/**
	 * @covers Provider_Encrypted_Options::is_available
	 */
	public function test_is_available() {
		$this->assertTrue( $this->provider->is_available() );
	}

	/**
	 * @covers Provider_Encrypted_Options::set
	 * @covers Provider_Encrypted_Options::get
	 */
	public function test_set_then_get_returns_same_value() {
		$this->provider->set( 'test/api_key', 'sk_live_abc123' );

		$this->assertSame( 'sk_live_abc123', $this->provider->get( 'test/api_key' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::set
	 * @covers Provider_Encrypted_Options::get
	 */
	public function test_set_overwrites_existing_value() {
		$this->provider->set( 'test/api_key', 'original_value' );
		$this->provider->set( 'test/api_key', 'updated_value' );

		$this->assertSame( 'updated_value', $this->provider->get( 'test/api_key' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::delete
	 */
	public function test_delete_returns_true_for_existing_key() {
		$this->provider->set( 'test/to_delete', 'some_value' );

		$this->assertTrue( $this->provider->delete( 'test/to_delete' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::delete
	 */
	public function test_delete_returns_false_for_nonexistent_key() {
		$this->assertFalse( $this->provider->delete( 'test/never_existed' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::exists
	 */
	public function test_exists_returns_false_for_nonexistent_key() {
		$this->assertFalse( $this->provider->exists( 'test/nonexistent' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::exists
	 */
	public function test_exists_returns_true_after_set() {
		$this->provider->set( 'test/exists_check', 'value' );

		$this->assertTrue( $this->provider->exists( 'test/exists_check' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::exists
	 */
	public function test_exists_returns_false_after_delete() {
		$this->provider->set( 'test/delete_check', 'value' );
		$this->provider->delete( 'test/delete_check' );

		$this->assertFalse( $this->provider->exists( 'test/delete_check' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_returns_empty_for_no_matches() {
		$this->assertSame( array(), $this->provider->list_keys( 'nonexistent/' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_returns_matching_keys() {
		$this->provider->set( 'alpha/one', 'v1' );
		$this->provider->set( 'alpha/two', 'v2' );
		$this->provider->set( 'beta/one', 'v3' );

		$keys = $this->provider->list_keys();

		$this->assertContains( 'alpha/one', $keys );
		$this->assertContains( 'alpha/two', $keys );
		$this->assertContains( 'beta/one', $keys );
	}

	/**
	 * @covers Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_filters_by_prefix() {
		$this->provider->set( 'alpha/one', 'v1' );
		$this->provider->set( 'alpha/two', 'v2' );
		$this->provider->set( 'beta/one', 'v3' );

		$keys = $this->provider->list_keys( 'alpha/' );

		$this->assertCount( 2, $keys );
		$this->assertContains( 'alpha/one', $keys );
		$this->assertContains( 'alpha/two', $keys );
	}

	/**
	 * @covers Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_excludes_master_key_option() {
		$this->provider->set( 'test/trigger', 'value' );

		$keys = $this->provider->list_keys();

		foreach ( $keys as $key ) {
			$this->assertNotSame( '_wp_secrets_master_key', Provider_Encrypted_Options::OPTION_PREFIX . $key );
		}
	}

	/**
	 * Verify the raw option value does not contain the plaintext secret.
	 *
	 * @covers Provider_Encrypted_Options::set
	 */
	public function test_stored_value_is_not_plaintext() {
		$plaintext = 'super_secret_api_key_12345';
		$this->provider->set( 'test/encrypted_check', $plaintext );

		$option_name = Provider_Encrypted_Options::option_name( 'test/encrypted_check' );
		$raw         = get_option( $option_name );

		$this->assertNotSame( $plaintext, $raw );
		$this->assertFalse( strpos( $raw, $plaintext ) );
	}

	/**
	 * Writing the same value twice should produce different ciphertext because
	 * a fresh nonce is generated on each encrypt call.
	 *
	 * @covers Provider_Encrypted_Options::set
	 */
	public function test_nonce_is_unique_per_write() {
		$option_name = Provider_Encrypted_Options::option_name( 'test/nonce_check' );

		$this->provider->set( 'test/nonce_check', 'same_value' );
		$raw_first = get_option( $option_name );

		$this->provider->set( 'test/nonce_check', 'same_value' );
		$raw_second = get_option( $option_name );

		$this->assertNotSame( $raw_first, $raw_second );
	}

	/**
	 * @covers Provider_Encrypted_Options::set
	 * @covers Provider_Encrypted_Options::get
	 */
	public function test_empty_string_value_stored_correctly() {
		$this->provider->set( 'test/empty', '' );

		$this->assertSame( '', $this->provider->get( 'test/empty' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::set
	 * @covers Provider_Encrypted_Options::get
	 */
	public function test_unicode_value_stored_correctly() {
		$unicode = '日本語テスト 🔑 émojis ñ ü ö';
		$this->provider->set( 'test/unicode', $unicode );

		$this->assertSame( $unicode, $this->provider->get( 'test/unicode' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::set
	 * @covers Provider_Encrypted_Options::get
	 */
	public function test_large_value_stored_correctly() {
		$large = str_repeat( 'A', 4096 );
		$this->provider->set( 'test/large', $large );

		$this->assertSame( $large, $this->provider->get( 'test/large' ) );
	}

	/**
	 * @covers Provider_Encrypted_Options::option_name
	 */
	public function test_option_name_preserves_key() {
		$this->assertSame(
			'_wp_secret_my-plugin/api_key',
			Provider_Encrypted_Options::option_name( 'my-plugin/api_key' )
		);
	}

	/**
	 * Secrets must be stored with autoload disabled to avoid polluting
	 * the global option cache on every page load.
	 *
	 * @covers Provider_Encrypted_Options::set
	 */
	public function test_autoload_is_disabled() {
		global $wpdb;

		$this->provider->set( 'test/autoload_check', 'value' );

		$option_name = Provider_Encrypted_Options::option_name( 'test/autoload_check' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$autoload = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT autoload FROM {$wpdb->options} WHERE option_name = %s",
				$option_name
			)
		);

		$this->assertSame( 'no', $autoload );
	}

	/**
	 * @covers Provider_Encrypted_Options::health_check
	 */
	public function test_health_check_returns_valid_status() {
		$result = $this->provider->health_check();

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'status', $result );
		$this->assertArrayHasKey( 'message', $result );
		$this->assertContains( $result['status'], array( 'good', 'recommended', 'critical' ) );
	}

	/**
	 * When WP_SECRETS_KEY is defined, the key source should be 'constant'.
	 *
	 * Note: We cannot redefine constants in a single PHP process. If
	 * WP_SECRETS_KEY is already defined in the test environment, this
	 * test verifies the 'constant' path. Otherwise it is skipped.
	 *
	 * @covers Provider_Encrypted_Options::get_key_source
	 */
	public function test_key_source_with_constant() {
		if ( ! defined( 'WP_SECRETS_KEY' ) ) {
			$this->markTestSkipped( 'WP_SECRETS_KEY is not defined in this environment.' );
		}

		$this->provider->reset_cache();

		$this->assertSame( 'constant', $this->provider->get_key_source() );
	}

	/**
	 * When WP_SECRETS_KEY is not defined, the fallback key source is used.
	 *
	 * Note: If WP_SECRETS_KEY is already defined, this test is skipped.
	 *
	 * @covers Provider_Encrypted_Options::get_key_source
	 */
	public function test_key_source_fallback() {
		if ( defined( 'WP_SECRETS_KEY' ) ) {
			$this->markTestSkipped( 'WP_SECRETS_KEY is defined; cannot test fallback path.' );
		}

		$this->provider->reset_cache();

		$this->assertSame( 'fallback', $this->provider->get_key_source() );
	}

	/**
	 * The master key option should be created on first use (i.e. first set()).
	 *
	 * @covers Provider_Encrypted_Options::set
	 */
	public function test_master_key_is_created_on_first_use() {
		$this->assertFalse(
			get_option( Provider_Encrypted_Options::MASTER_KEY_OPTION, false ),
			'Master key option should not exist before any operation.'
		);

		$this->provider->set( 'test/trigger_master', 'value' );

		$this->assertNotFalse(
			get_option( Provider_Encrypted_Options::MASTER_KEY_OPTION, false ),
			'Master key option should exist after a set() call.'
		);
	}

	/**
	 * Setting two different secrets should reuse the same master key
	 * rather than generating a new one each time.
	 *
	 * @covers Provider_Encrypted_Options::set
	 */
	public function test_master_key_reused_across_operations() {
		global $wpdb;

		$this->provider->set( 'test/first', 'value1' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$master_after_first = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				Provider_Encrypted_Options::MASTER_KEY_OPTION
			)
		);

		$this->provider->set( 'test/second', 'value2' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$master_after_second = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				Provider_Encrypted_Options::MASTER_KEY_OPTION
			)
		);

		$this->assertSame(
			$master_after_first,
			$master_after_second,
			'Master key option value should not change between operations.'
		);
	}
}
