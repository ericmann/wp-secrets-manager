<?php
/**
 * Tests for WP-CLI command logic via WP_Secrets_Manager.
 *
 * Since WP-CLI cannot be invoked directly in unit tests, these tests
 * exercise the underlying manager methods with the same context that
 * the CLI commands construct (is_cli = true, global flag, etc.).
 *
 * @package WP_Secrets_Manager
 * @group   cli
 */

class Test_CLI extends WP_UnitTestCase {

	/**
	 * Manager instance.
	 *
	 * @var WP_Secrets_Manager
	 */
	private $manager;

	/**
	 * Provider instance.
	 *
	 * @var Provider_Encrypted_Options
	 */
	private $provider;

	/**
	 * Keys written during a test, cleaned up in tearDown.
	 *
	 * @var string[]
	 */
	private $created_keys = array();

	/**
	 * Set up each test.
	 */
	public function setUp(): void {
		parent::setUp();

		WP_Secrets_Manager::reset();

		$this->provider = new Provider_Encrypted_Options();
		$this->provider->reset_cache();

		$this->manager = WP_Secrets_Manager::get_instance();
		$this->manager->register_provider( $this->provider );
		$this->manager->select_provider();
	}

	/**
	 * Tear down each test.
	 */
	public function tearDown(): void {
		foreach ( $this->created_keys as $key ) {
			delete_option( Provider_Encrypted_Options::option_name( $key ) );
		}

		delete_option( Provider_Encrypted_Options::MASTER_KEY_OPTION );

		$this->created_keys = array();

		WP_Secrets_Manager::reset();

		parent::tearDown();
	}

	/**
	 * Track a key so it is cleaned up in tearDown.
	 *
	 * @param string $key Secret key.
	 */
	private function track_key( string $key ): void {
		$this->created_keys[] = $key;
	}

	/**
	 * Build a CLI-style context array.
	 *
	 * @param array $overrides Additional context values.
	 * @return array
	 */
	private function cli_context( array $overrides = [] ): array {
		return array_merge( array( 'is_cli' => true ), $overrides );
	}

	/**
	 * @covers WP_Secrets_Manager::set
	 */
	public function test_set_via_manager_stores_secret() {
		$key   = 'cli-test/api_key';
		$value = 'sk_live_test_123';

		$this->track_key( $key );

		$result = $this->manager->set( $key, $value, $this->cli_context() );

		$this->assertTrue( $result );
	}

	/**
	 * @covers WP_Secrets_Manager::get
	 */
	public function test_get_via_manager_retrieves_secret() {
		$key   = 'cli-test/retrieve_key';
		$value = 'secret-payload-abc';

		$this->track_key( $key );
		$this->manager->set( $key, $value, $this->cli_context() );

		$retrieved = $this->manager->get( $key, $this->cli_context() );

		$this->assertSame( $value, $retrieved );
	}

	/**
	 * @covers WP_Secrets_Manager::delete
	 */
	public function test_delete_via_manager_removes_secret() {
		$key   = 'cli-test/delete_key';
		$value = 'to-be-deleted';

		$this->track_key( $key );
		$this->manager->set( $key, $value, $this->cli_context() );

		$deleted = $this->manager->delete( $key, $this->cli_context() );

		$this->assertTrue( $deleted );
		$this->assertNull( $this->manager->get( $key, $this->cli_context() ) );
	}

	/**
	 * @covers WP_Secrets_Manager::list_keys
	 */
	public function test_list_keys_via_manager() {
		$keys = array(
			'cli-test/key_alpha',
			'cli-test/key_beta',
			'cli-test/key_gamma',
		);

		foreach ( $keys as $key ) {
			$this->track_key( $key );
			$this->manager->set( $key, 'value-' . $key, $this->cli_context() );
		}

		$listed = $this->manager->list_keys( 'cli-test/', $this->cli_context() );

		$this->assertCount( 3, $listed );
		foreach ( $keys as $key ) {
			$this->assertContains( $key, $listed );
		}
	}

	/**
	 * @covers WP_Secrets_Manager::exists
	 */
	public function test_exists_returns_true_for_stored() {
		$key = 'cli-test/exists_key';
		$this->track_key( $key );
		$this->manager->set( $key, 'some-value', $this->cli_context() );

		$this->assertTrue( $this->manager->exists( $key, $this->cli_context() ) );
	}

	/**
	 * @covers WP_Secrets_Manager::exists
	 */
	public function test_exists_returns_false_for_missing() {
		$this->assertFalse(
			$this->manager->exists( 'cli-test/nonexistent', $this->cli_context() )
		);
	}

	/**
	 * @covers WP_Secrets_Manager::set
	 * @covers WP_Secrets_Manager::get
	 */
	public function test_global_key_via_manager() {
		$key     = 'infrastructure_master';
		$value   = 'global-secret-value';
		$context = $this->cli_context( array( 'global' => true ) );

		$this->track_key( $key );

		$result = $this->manager->set( $key, $value, $context );

		$this->assertTrue( $result );
		$this->assertSame( $value, $this->manager->get( $key, $context ) );
	}

	/**
	 * CLI context (is_cli = true) should bypass namespace restrictions,
	 * allowing read access to secrets set by another plugin.
	 *
	 * @covers WP_Secrets_Manager::get
	 * @covers WP_Secrets_Context::can_access_namespace
	 */
	public function test_cli_bypasses_namespace_restriction() {
		$key   = 'plugin-a/private_token';
		$value = 'token-from-plugin-a';

		$this->track_key( $key );

		$plugin_a_context = array( 'plugin' => 'plugin-a' );
		$this->manager->set( $key, $value, $plugin_a_context );

		$cli_value = $this->manager->get( $key, $this->cli_context() );

		$this->assertSame( $value, $cli_value );
	}
}
