<?php
/**
 * WP Secrets Site Health Integration
 *
 * Adds checks to WordPress Site Health (Tools > Site Health) to report
 * on the security posture of the secrets storage system.
 *
 * @package WP_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Site Health checks for secrets management.
 */
class WP_Secrets_Health_Check {

	/**
	 * Constructor — registers Site Health hooks.
	 */
	public function __construct() {
		add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_info' ) );
	}

	/**
	 * Register Site Health tests.
	 *
	 * @param array $tests Existing tests.
	 * @return array
	 */
	public function register_tests( array $tests ): array {
		$tests['direct']['wp_secrets_provider'] = array(
			'label' => __( 'Secrets Provider', 'wp-secrets-manager' ),
			'test'  => array( $this, 'test_provider_health' ),
		);

		$tests['direct']['wp_secrets_encryption'] = array(
			'label' => __( 'Secrets Encryption', 'wp-secrets-manager' ),
			'test'  => array( $this, 'test_encryption_health' ),
		);

		return $tests;
	}

	/**
	 * Test: Active provider health.
	 *
	 * @return array Site Health test result.
	 */
	public function test_provider_health(): array {
		$manager  = WP_Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( null === $provider ) {
			return array(
				'label'       => __( 'No secrets provider is active', 'wp-secrets-manager' ),
				'status'      => 'critical',
				'badge'       => array(
					'label' => __( 'Security', 'wp-secrets-manager' ),
					'color' => 'red',
				),
				'description' => sprintf(
					'<p>%s</p>',
					__( 'WP Secrets Manager has no active provider. Secrets cannot be stored or retrieved. The sodium PHP extension may not be available.', 'wp-secrets-manager' )
				),
				'actions'     => '',
				'test'        => 'wp_secrets_provider',
			);
		}

		$health = $provider->health_check();
		$status = $health['status'];

		$color_map = array(
			'good'        => 'blue',
			'recommended' => 'orange',
			'critical'    => 'red',
		);

		$label_map = array(
			'good'        => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" is healthy', 'wp-secrets-manager' ),
				$provider->get_name()
			),
			'recommended' => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" could be improved', 'wp-secrets-manager' ),
				$provider->get_name()
			),
			'critical'    => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" has a critical issue', 'wp-secrets-manager' ),
				$provider->get_name()
			),
		);

		return array(
			'label'       => $label_map[ $status ] ?? $label_map['critical'],
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'wp-secrets-manager' ),
				'color' => $color_map[ $status ] ?? 'red',
			),
			'description' => sprintf( '<p>%s</p>', esc_html( $health['message'] ) ),
			'actions'     => '',
			'test'        => 'wp_secrets_provider',
		);
	}

	/**
	 * Test: Encryption key configuration.
	 *
	 * @return array Site Health test result.
	 */
	public function test_encryption_health(): array {
		$manager  = WP_Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( ! $provider instanceof Provider_Encrypted_Options ) {
			return array(
				'label'       => __( 'Secrets storage is configured', 'wp-secrets-manager' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'wp-secrets-manager' ),
					'color' => 'blue',
				),
				'description' => sprintf(
					'<p>%s</p>',
					sprintf(
						/* translators: %s: provider name */
						__( 'Secrets are managed by the "%s" provider.', 'wp-secrets-manager' ),
						$provider ? $provider->get_name() : __( 'Unknown', 'wp-secrets-manager' )
					)
				),
				'actions'     => '',
				'test'        => 'wp_secrets_encryption',
			);
		}

		$key_source = $provider->get_key_source();

		if ( Provider_Encrypted_Options::KEY_SOURCE_FALLBACK === $key_source ) {
			return array(
				'label'       => __( 'Secrets encrypted with key derived from WordPress salts', 'wp-secrets-manager' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'wp-secrets-manager' ),
					'color' => 'orange',
				),
				'description' => sprintf(
					'<p>%s</p><p>%s</p>',
					__( 'Secrets are encrypted at rest, but the encryption key is derived from LOGGED_IN_KEY and LOGGED_IN_SALT.', 'wp-secrets-manager' ),
					__( 'Define a dedicated WP_SECRETS_KEY in wp-config.php for independent key management. Generate one with: wp secret generate-key', 'wp-secrets-manager' )
				),
				'actions'     => '',
				'test'        => 'wp_secrets_encryption',
			);
		}

		return array(
			'label'       => __( 'Secrets are encrypted with a dedicated key', 'wp-secrets-manager' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'wp-secrets-manager' ),
				'color' => 'blue',
			),
			'description' => sprintf(
				'<p>%s</p>',
				__( 'Secrets are encrypted at rest using sodium_crypto_secretbox with a dedicated WP_SECRETS_KEY. The master key architecture means key rotation only re-encrypts one value.', 'wp-secrets-manager' )
			),
			'actions'     => '',
			'test'        => 'wp_secrets_encryption',
		);
	}

	/**
	 * Add debug information to Site Health Info tab.
	 *
	 * @param array $info Existing debug info.
	 * @return array
	 */
	public function add_debug_info( array $info ): array {
		$manager   = WP_Secrets_Manager::get_instance();
		$provider  = $manager->get_active_provider();
		$providers = $manager->get_providers();

		$fields = array(
			'version'          => array(
				'label' => __( 'Plugin Version', 'wp-secrets-manager' ),
				'value' => WP_SECRETS_MANAGER_VERSION,
			),
			'active_provider'  => array(
				'label' => __( 'Active Provider', 'wp-secrets-manager' ),
				'value' => $provider ? $provider->get_name() . ' (' . $provider->get_id() . ')' : __( 'None', 'wp-secrets-manager' ),
			),
			'provider_count'   => array(
				'label' => __( 'Registered Providers', 'wp-secrets-manager' ),
				'value' => count( $providers ),
			),
			'sodium_available' => array(
				'label' => __( 'Sodium Available', 'wp-secrets-manager' ),
				'value' => function_exists( 'sodium_crypto_secretbox' ) ? __( 'Yes', 'wp-secrets-manager' ) : __( 'No', 'wp-secrets-manager' ),
			),
		);

		if ( $provider instanceof Provider_Encrypted_Options ) {
			$fields['key_source'] = array(
				'label' => __( 'Key Source', 'wp-secrets-manager' ),
				'value' => $provider->get_key_source(),
			);
			$fields['has_previous_key'] = array(
				'label' => __( 'Previous Key Configured', 'wp-secrets-manager' ),
				'value' => defined( 'WP_SECRETS_KEY_PREVIOUS' ) ? __( 'Yes', 'wp-secrets-manager' ) : __( 'No', 'wp-secrets-manager' ),
			);
			$fields['master_key_exists'] = array(
				'label' => __( 'Master Key Stored', 'wp-secrets-manager' ),
				'value' => false !== get_option( Provider_Encrypted_Options::MASTER_KEY_OPTION, false ) ? __( 'Yes', 'wp-secrets-manager' ) : __( 'No (will be created on first use)', 'wp-secrets-manager' ),
			);
		}

		if ( $provider ) {
			$health = $provider->health_check();
			$fields['health_status'] = array(
				'label' => __( 'Health Status', 'wp-secrets-manager' ),
				'value' => $health['status'] . ' — ' . $health['message'],
			);
		}

		$info['wp-secrets-manager'] = array(
			'label'  => __( 'WP Secrets Manager', 'wp-secrets-manager' ),
			'fields' => $fields,
		);

		return $info;
	}
}
