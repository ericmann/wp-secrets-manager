<?php
/**
 * Tests for WP_Secrets_Audit.
 *
 * @package WP_Secrets_Manager
 * @group audit
 */

class Test_WP_Secrets_Audit extends WP_UnitTestCase {

	/**
	 * Captured hook calls for verification.
	 *
	 * @var array
	 */
	private $hook_calls = array();

	public function set_up() {
		parent::set_up();
		$this->hook_calls = array();
	}

	public function tear_down() {
		remove_all_actions( 'wp_secrets_accessed' );
		remove_all_actions( 'wp_secrets_get' );
		remove_all_actions( 'wp_secrets_set' );
		remove_all_actions( 'wp_secrets_delete' );
		parent::tear_down();
	}

	public function test_log_fires_accessed_action() {
		add_action(
			'wp_secrets_accessed',
			function ( $key, $operation, $context ) {
				$this->hook_calls['accessed'] = array(
					'key'       => $key,
					'operation' => $operation,
					'context'   => $context,
				);
			},
			10,
			3
		);

		WP_Secrets_Audit::log( 'get', 'foo/bar', array( 'plugin' => 'foo' ) );

		$this->assertArrayHasKey( 'accessed', $this->hook_calls );
		$this->assertSame( 'foo/bar', $this->hook_calls['accessed']['key'] );
		$this->assertSame( 'get', $this->hook_calls['accessed']['operation'] );
		$this->assertSame( 'foo', $this->hook_calls['accessed']['context']['plugin'] );
	}

	/**
	 * @dataProvider data_operations
	 */
	public function test_log_fires_operation_specific_action( $operation ) {
		$captured = null;

		add_action(
			"wp_secrets_{$operation}",
			function ( $key, $context ) use ( &$captured ) {
				$captured = array(
					'key'     => $key,
					'context' => $context,
				);
			},
			10,
			2
		);

		WP_Secrets_Audit::log( $operation, 'test/secret', array( 'plugin' => 'test' ) );

		$this->assertNotNull( $captured, "wp_secrets_{$operation} action should fire" );
		$this->assertSame( 'test/secret', $captured['key'] );
	}

	public function data_operations() {
		return array(
			'get'    => array( 'get' ),
			'set'    => array( 'set' ),
			'delete' => array( 'delete' ),
		);
	}

	public function test_context_includes_operation() {
		$captured_context = null;

		add_action(
			'wp_secrets_accessed',
			function ( $key, $operation, $context ) use ( &$captured_context ) {
				$captured_context = $context;
			},
			10,
			3
		);

		WP_Secrets_Audit::log( 'set', 'ns/key', array() );

		$this->assertArrayHasKey( 'operation', $captured_context );
		$this->assertSame( 'set', $captured_context['operation'] );
	}

	public function test_context_includes_timestamp() {
		$captured_context = null;

		add_action(
			'wp_secrets_accessed',
			function ( $key, $operation, $context ) use ( &$captured_context ) {
				$captured_context = $context;
			},
			10,
			3
		);

		WP_Secrets_Audit::log( 'get', 'ns/key', array() );

		$this->assertArrayHasKey( 'timestamp', $captured_context );
		$this->assertNotEmpty( $captured_context['timestamp'] );
	}

	public function test_context_includes_user_id() {
		$user_id = self::factory()->user->create();
		wp_set_current_user( $user_id );

		$captured_context = null;

		add_action(
			'wp_secrets_accessed',
			function ( $key, $operation, $context ) use ( &$captured_context ) {
				$captured_context = $context;
			},
			10,
			3
		);

		WP_Secrets_Audit::log( 'delete', 'ns/key', array() );

		$this->assertArrayHasKey( 'user_id', $captured_context );
		$this->assertSame( $user_id, $captured_context['user_id'] );
	}

	public function test_set_action_does_not_receive_value() {
		$captured_context = null;

		add_action(
			'wp_secrets_set',
			function ( $key, $context ) use ( &$captured_context ) {
				$captured_context = $context;
			},
			10,
			2
		);

		WP_Secrets_Audit::log( 'set', 'ns/api_key', array( 'plugin' => 'ns' ) );

		$this->assertNotNull( $captured_context );
		$this->assertArrayNotHasKey( 'value', $captured_context );
		$this->assertArrayNotHasKey( 'secret', $captured_context );
		$this->assertArrayNotHasKey( 'secret_value', $captured_context );

		foreach ( $captured_context as $v ) {
			if ( is_string( $v ) ) {
				$this->assertStringNotContainsString( 'sk_live_', $v );
			}
		}
	}
}
