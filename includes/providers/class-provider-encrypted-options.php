<?php
/**
 * Encrypted Options Provider
 *
 * Stores secrets in wp_options encrypted with sodium_crypto_secretbox
 * (XSalsa20-Poly1305). The encryption key is resolved in priority order:
 *
 *   1. WP_SECRETS_KEY constant (recommended)
 *   2. WP_SECRETS_KEY environment variable
 *   3. LOGGED_IN_KEY . LOGGED_IN_SALT fallback
 *
 * Each write generates a unique nonce prepended to the ciphertext,
 * making the stored value self-contained for decryption.
 *
 * @package WP_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypted secrets storage using libsodium and wp_options.
 */
class Provider_Encrypted_Options implements WP_Secrets_Provider {

	/**
	 * Prefix applied to option names.
	 *
	 * @var string
	 */
	const OPTION_PREFIX = '_wp_secret_';

	/**
	 * Key source constants for health reporting.
	 */
	const KEY_SOURCE_CONSTANT = 'constant';
	const KEY_SOURCE_ENV      = 'env';
	const KEY_SOURCE_FALLBACK = 'fallback';
	const KEY_SOURCE_NONE     = 'none';

	/**
	 * Cached derived encryption key.
	 *
	 * @var string|null
	 */
	private $key_cache = null;

	/**
	 * Cached key source identifier.
	 *
	 * @var string|null
	 */
	private $key_source_cache = null;

	/**
	 * {@inheritDoc}
	 */
	public function get_id(): string {
		return 'encrypted-options';
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_name(): string {
		return __( 'Encrypted Options', 'wp-secrets-manager' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_priority(): int {
		return 50;
	}

	/**
	 * Available when the sodium extension is loaded and a key can be derived.
	 *
	 * {@inheritDoc}
	 */
	public function is_available(): bool {
		if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
			return false;
		}

		return self::KEY_SOURCE_NONE !== $this->get_key_source();
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key, array $context = [] ): ?string {
		$option_name = self::option_name( $key );
		$raw         = get_option( $option_name, null );

		if ( null === $raw || false === $raw ) {
			return null;
		}

		return $this->decrypt( $raw, $key );
	}

	/**
	 * {@inheritDoc}
	 */
	public function set( string $key, string $value, array $context = [] ): bool {
		$option_name = self::option_name( $key );
		$encrypted   = $this->encrypt( $value, $key );

		if ( false === get_option( $option_name ) ) {
			return add_option( $option_name, $encrypted, '', 'no' );
		}

		return update_option( $option_name, $encrypted, 'no' );
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
		$source = $this->get_key_source();

		if ( self::KEY_SOURCE_NONE === $source ) {
			return array(
				'status'  => 'critical',
				'message' => __( 'No encryption key available. Define WP_SECRETS_KEY in wp-config.php.', 'wp-secrets-manager' ),
			);
		}

		// Verify round-trip.
		try {
			$test_plaintext = 'wp-secrets-health-check-' . wp_generate_password( 12, false );
			$ciphertext     = $this->encrypt( $test_plaintext, '__health_check__' );
			$decrypted      = $this->decrypt( $ciphertext, '__health_check__' );

			if ( $test_plaintext !== $decrypted ) {
				return array(
					'status'  => 'critical',
					'message' => __( 'Encryption round-trip failed. The encryption key may be corrupted.', 'wp-secrets-manager' ),
				);
			}
		} catch ( WP_Secrets_Exception $e ) {
			return array(
				'status'  => 'critical',
				'message' => $e->getMessage(),
			);
		}

		if ( self::KEY_SOURCE_FALLBACK === $source ) {
			return array(
				'status'  => 'recommended',
				'message' => __( 'Encryption active using fallback key (LOGGED_IN_KEY). Define a dedicated WP_SECRETS_KEY in wp-config.php for better security.', 'wp-secrets-manager' ),
			);
		}

		return array(
			'status'  => 'good',
			'message' => sprintf(
				/* translators: %s: key source (constant or env) */
				__( 'Encryption active with dedicated key (source: %s).', 'wp-secrets-manager' ),
				$source
			),
		);
	}

	/**
	 * Encrypt a plaintext value.
	 *
	 * @param string $plaintext The value to encrypt.
	 * @param string $key       The secret key name (for error context only).
	 * @return string Base64-encoded nonce + ciphertext.
	 *
	 * @throws WP_Secrets_Exception If encryption fails.
	 */
	private function encrypt( string $plaintext, string $key ): string {
		$encryption_key = $this->derive_key();

		try {
			$nonce      = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $encryption_key );
		} catch ( \Exception $e ) {
			throw new WP_Secrets_Exception(
				__( 'Encryption failed.', 'wp-secrets-manager' ),
				0,
				$e,
				$key,
				$this->get_id()
			);
		}

		return base64_encode( $nonce . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decrypt a stored value.
	 *
	 * @param string $stored The base64-encoded nonce + ciphertext.
	 * @param string $key    The secret key name (for error context only).
	 * @return string The decrypted plaintext.
	 *
	 * @throws WP_Secrets_Exception If decryption fails.
	 */
	private function decrypt( string $stored, string $key ): string {
		$encryption_key = $this->derive_key();

		$decoded = base64_decode( $stored, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $decoded ) {
			throw new WP_Secrets_Exception(
				__( 'Invalid stored ciphertext (base64 decode failed).', 'wp-secrets-manager' ),
				0,
				null,
				$key,
				$this->get_id()
			);
		}

		if ( strlen( $decoded ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			throw new WP_Secrets_Exception(
				__( 'Stored ciphertext is too short to contain a valid nonce and payload.', 'wp-secrets-manager' ),
				0,
				null,
				$key,
				$this->get_id()
			);
		}

		$nonce      = substr( $decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$ciphertext = substr( $decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		try {
			$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $encryption_key );
		} catch ( \SodiumException $e ) {
			throw new WP_Secrets_Exception(
				__( 'Decryption failed. The encryption key may have changed.', 'wp-secrets-manager' ),
				0,
				$e,
				$key,
				$this->get_id()
			);
		}

		if ( false === $plaintext ) {
			throw new WP_Secrets_Exception(
				__( 'Decryption failed. The encryption key may have changed or the data is corrupt.', 'wp-secrets-manager' ),
				0,
				null,
				$key,
				$this->get_id()
			);
		}

		return $plaintext;
	}

	/**
	 * Derive the 32-byte encryption key from the best available source.
	 *
	 * @return string 32-byte binary key.
	 *
	 * @throws WP_Secrets_Exception If no key source is available.
	 */
	private function derive_key(): string {
		if ( null !== $this->key_cache ) {
			return $this->key_cache;
		}

		$source = $this->get_key_source();

		if ( self::KEY_SOURCE_NONE === $source ) {
			throw new WP_Secrets_Exception(
				__( 'No encryption key available. Define WP_SECRETS_KEY in wp-config.php or as an environment variable.', 'wp-secrets-manager' ),
				0,
				null,
				'',
				$this->get_id()
			);
		}

		$raw_key = $this->get_raw_key_material( $source );

		// If the key starts with 'base64:', decode it directly.
		if ( 0 === strpos( $raw_key, 'base64:' ) ) {
			$decoded = base64_decode( substr( $raw_key, 7 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false !== $decoded && SODIUM_CRYPTO_SECRETBOX_KEYBYTES === strlen( $decoded ) ) {
				$this->key_cache = $decoded;
				return $this->key_cache;
			}
		}

		// Derive a fixed-length key via BLAKE2b hash.
		$this->key_cache = sodium_crypto_generichash( $raw_key, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );

		return $this->key_cache;
	}

	/**
	 * Determine the key source without resolving the key itself.
	 *
	 * @return string One of the KEY_SOURCE_* constants.
	 */
	public function get_key_source(): string {
		if ( null !== $this->key_source_cache ) {
			return $this->key_source_cache;
		}

		if ( defined( 'WP_SECRETS_KEY' ) && '' !== WP_SECRETS_KEY ) {
			$this->key_source_cache = self::KEY_SOURCE_CONSTANT;
		} elseif ( false !== getenv( 'WP_SECRETS_KEY' ) && '' !== getenv( 'WP_SECRETS_KEY' ) ) {
			$this->key_source_cache = self::KEY_SOURCE_ENV;
		} elseif ( defined( 'LOGGED_IN_KEY' ) && defined( 'LOGGED_IN_SALT' ) && '' !== LOGGED_IN_KEY && '' !== LOGGED_IN_SALT ) {
			$this->key_source_cache = self::KEY_SOURCE_FALLBACK;
		} else {
			$this->key_source_cache = self::KEY_SOURCE_NONE;
		}

		return $this->key_source_cache;
	}

	/**
	 * Retrieve the raw key material for a given source.
	 *
	 * @param string $source One of the KEY_SOURCE_* constants.
	 * @return string Raw key material.
	 */
	private function get_raw_key_material( string $source ): string {
		switch ( $source ) {
			case self::KEY_SOURCE_CONSTANT:
				return WP_SECRETS_KEY;

			case self::KEY_SOURCE_ENV:
				return getenv( 'WP_SECRETS_KEY' );

			case self::KEY_SOURCE_FALLBACK:
				return LOGGED_IN_KEY . LOGGED_IN_SALT;

			default:
				return '';
		}
	}

	/**
	 * Build the wp_options option_name for a given secret key.
	 *
	 * Uses the same prefix as the plaintext provider so migrations
	 * between the two only require re-encrypting values in place.
	 *
	 * @param string $key The secret key.
	 * @return string
	 */
	public static function option_name( string $key ): string {
		return self::OPTION_PREFIX . str_replace( '/', '_', $key );
	}
}
