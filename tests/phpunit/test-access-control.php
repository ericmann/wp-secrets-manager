<?php
/**
 * Tests for access control in WP_Secrets_Manager and WP_Secrets_Context.
 *
 * @package WP_Secrets_Manager
 * @group access-control
 */

class Test_Access_Control extends WP_UnitTestCase {

	/**
	 * Manager instance used across tests.
	 *
	 * @var WP_Secrets_Manager
	 */
	private $manager;

	/**
	 * Captured hook calls for verification.
	 *
	 * @var array
	 */
	private $hook_calls = array();

	public function set_up() {
		parent::set_up();

		$this->hook_calls = array();
		$this->manager    = WP_Secrets_Manager::get_instance();
	}

	public function tear_down() {
		remove_all_filters( 'wp_secrets_access' );
		remove_all_actions( 'wp_secrets_access_denied' );
		WP_Secrets_Manager::reset();
		parent::tear_down();
	}

	public function test_cli_context_bypasses_restriction() {
		$context = array(
			'plugin' => 'some-plugin',
			'is_cli' => true,
		);

		$allowed = $this->manager->check_access( 'another-plugin/secret', 'get', $context );

		$this->assertTrue( $allowed );
	}

	public function test_same_namespace_allowed() {
		$context = array(
			'plugin' => 'foo',
			'is_cli' => false,
		);

		$allowed = $this->manager->check_access( 'foo/secret', 'get', $context );

		$this->assertTrue( $allowed );
	}

	public function test_cross_namespace_denied_without_capability() {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$context = array(
			'plugin'  => 'foo',
			'user_id' => $user_id,
			'is_cli'  => false,
		);

		$allowed = $this->manager->check_access( 'bar/secret', 'get', $context );

		$this->assertFalse( $allowed );
	}

	public function test_admin_can_access_any_namespace() {
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );

		$role = get_role( 'administrator' );
		$role->add_cap( 'manage_secrets' );

		$context = array(
			'plugin'  => 'foo',
			'user_id' => $user_id,
			'is_cli'  => false,
		);

		$allowed = $this->manager->check_access( 'bar/secret', 'get', $context );

		$role->remove_cap( 'manage_secrets' );

		$this->assertTrue( $allowed );
	}

	public function test_access_filter_can_grant() {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		add_filter(
			'wp_secrets_access',
			function ( $allowed, $key, $operation, $context ) {
				if ( 'bar/secret' === $key && 'monitor' === $context['plugin'] ) {
					return true;
				}
				return $allowed;
			},
			10,
			4
		);

		$context = array(
			'plugin'  => 'monitor',
			'user_id' => $user_id,
			'is_cli'  => false,
		);

		$allowed = $this->manager->check_access( 'bar/secret', 'get', $context );

		$this->assertTrue( $allowed );
	}

	public function test_access_filter_can_deny() {
		add_filter(
			'wp_secrets_access',
			function ( $allowed, $key, $operation, $context ) {
				if ( 'restricted/secret' === $key ) {
					return false;
				}
				return $allowed;
			},
			10,
			4
		);

		$context = array(
			'plugin' => 'restricted',
			'is_cli' => false,
		);

		$allowed = $this->manager->check_access( 'restricted/secret', 'get', $context );

		$this->assertFalse( $allowed );
	}

	public function test_access_denied_action_fires() {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		add_action(
			'wp_secrets_access_denied',
			function ( $key, $operation, $context ) {
				$this->hook_calls['access_denied'] = array(
					'key'       => $key,
					'operation' => $operation,
					'context'   => $context,
				);
			},
			10,
			3
		);

		$mock_provider = $this->createMock( WP_Secrets_Provider::class );
		$mock_provider->method( 'get_id' )->willReturn( 'mock' );
		$mock_provider->method( 'is_available' )->willReturn( true );
		$mock_provider->method( 'get_priority' )->willReturn( 10 );

		$this->manager->register_provider( $mock_provider );
		$this->manager->select_provider();

		$context = array(
			'plugin'  => 'foo',
			'user_id' => $user_id,
			'is_cli'  => false,
		);

		$this->manager->get( 'bar/secret', $context );

		$this->assertArrayHasKey( 'access_denied', $this->hook_calls );
		$this->assertSame( 'bar/secret', $this->hook_calls['access_denied']['key'] );
		$this->assertSame( 'get', $this->hook_calls['access_denied']['operation'] );
	}
}
