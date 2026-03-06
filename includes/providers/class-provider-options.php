<?php
/**
 * Plaintext Options Provider
 *
 * Stores secrets in wp_options as plaintext. This is the fallback
 * provider that ensures get_secret()/set_secret() always work, even
 * on environments with no encryption key or sodium extension.
 *
 * When active, Site Health displays a recommendation to upgrade.
 *
 * @package WP_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores secrets as plaintext values in the wp_options table.
 */
class Provider_Options implements WP_Secrets_Provider {

	/**
	 * Prefix applied to option names to namespace secret storage.
	 *
	 * @var string
	 */
	const OPTION_PREFIX = '_wp_secret_';

	/**
	 * {@inheritDoc}
	 */
	public function get_id(): string {
		return 'options';
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_name(): string {
		return __( 'Plaintext Options', 'wp-secrets-manager' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_priority(): int {
		return 10;
	}

	/**
	 * Always available — wp_options exists on every WordPress install.
	 *
	 * {@inheritDoc}
	 */
	public function is_available(): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key, array $context = [] ): ?string {
		$option_name = self::option_name( $key );
		$value       = get_option( $option_name, null );

		if ( null === $value || false === $value ) {
			return null;
		}

		return (string) $value;
	}

	/**
	 * {@inheritDoc}
	 */
	public function set( string $key, string $value, array $context = [] ): bool {
		$option_name = self::option_name( $key );

		// Use update_option with autoload disabled; wp_options should
		// never eager-load secret values into the global cache.
		if ( false === get_option( $option_name ) ) {
			return add_option( $option_name, $value, '', 'no' );
		}

		return update_option( $option_name, $value, 'no' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function delete( string $key, array $context = [] ): bool {
		return delete_option( self::option_name( $key ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function exists( string $key, array $context = [] ): bool {
		return false !== get_option( self::option_name( $key ), false );
	}

	/**
	 * {@inheritDoc}
	 */
	public function list_keys( string $prefix = '', array $context = [] ): array {
		global $wpdb;

		$like = $wpdb->esc_like( self::OPTION_PREFIX . $prefix ) . '%';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- listing secret keys requires direct query.
		$results = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s ORDER BY option_name ASC",
				$like
			)
		);

		$prefix_length = strlen( self::OPTION_PREFIX );

		return array_map(
			function ( $option_name ) use ( $prefix_length ) {
				return substr( $option_name, $prefix_length );
			},
			$results
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function health_check(): array {
		return array(
			'status'  => 'recommended',
			'message' => __( 'Secrets are stored as plaintext in the database. Enable encryption or configure a remote secrets backend for better security.', 'wp-secrets-manager' ),
		);
	}

	/**
	 * Build the wp_options option_name for a given secret key.
	 *
	 * @param string $key The secret key.
	 * @return string
	 */
	public static function option_name( string $key ): string {
		return self::OPTION_PREFIX . str_replace( '/', '_', $key );
	}
}
