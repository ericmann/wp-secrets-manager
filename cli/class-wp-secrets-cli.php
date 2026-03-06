<?php
/**
 * WP-CLI Commands for WP Secrets Manager
 *
 * Provides the `wp secret` command family for managing secrets
 * from the command line.
 *
 * @package WP_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_CLI_Command' ) ) {
	return;
}

/**
 * Manage secrets stored by WP Secrets Manager.
 *
 * ## EXAMPLES
 *
 *     # Store a secret
 *     wp secret set my-plugin/api_key sk_live_abc123
 *
 *     # Store from stdin (avoids shell history)
 *     echo "sk_live_abc123" | wp secret set my-plugin/api_key --stdin
 *
 *     # Retrieve a secret (masked by default)
 *     wp secret get my-plugin/api_key
 *
 *     # Retrieve with visible value
 *     wp secret get my-plugin/api_key --reveal
 *
 *     # List all secrets
 *     wp secret list
 *
 *     # Show provider info
 *     wp secret provider
 */
class WP_Secrets_CLI extends WP_CLI_Command {

	/**
	 * Store a secret.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The namespaced secret key (e.g. my-plugin/api_key).
	 *
	 * [<value>]
	 * : The secret value. Omit if using --stdin.
	 *
	 * [--stdin]
	 * : Read the secret value from stdin.
	 *
	 * [--global]
	 * : Allow storing without a namespace prefix.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret set stripe/secret_key sk_live_abc123
	 *     echo "sk_live_abc123" | wp secret set stripe/secret_key --stdin
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function set( $args, $assoc_args ) {
		$key = $args[0];

		if ( \WP_CLI\Utils\get_flag_value( $assoc_args, 'stdin' ) ) {
			$value = trim( file_get_contents( 'php://stdin' ) );
			if ( '' === $value ) {
				WP_CLI::error( 'No value received from stdin.' );
			}
		} elseif ( isset( $args[1] ) ) {
			$value = $args[1];
		} else {
			WP_CLI::error( 'Provide a value as the second argument or use --stdin.' );
		}

		$context = array(
			'is_cli' => true,
			'global' => \WP_CLI\Utils\get_flag_value( $assoc_args, 'global', false ),
		);

		$manager = WP_Secrets_Manager::get_instance();
		$valid   = $manager->validate_key( $key, $context );

		if ( is_wp_error( $valid ) ) {
			WP_CLI::error( $valid->get_error_message() );
		}

		try {
			$result = $manager->set( $key, $value, $context );
		} catch ( WP_Secrets_Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}

		if ( $result ) {
			WP_CLI::success( sprintf( 'Secret "%s" stored.', $key ) );
		} else {
			WP_CLI::error( sprintf( 'Failed to store secret "%s".', $key ) );
		}
	}

	/**
	 * Retrieve a secret.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The secret key to retrieve.
	 *
	 * [--reveal]
	 * : Show the actual value instead of a masked placeholder.
	 *
	 * [--global]
	 * : Allow retrieval of unnamespaced keys.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret get stripe/secret_key
	 *     wp secret get stripe/secret_key --reveal
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function get( $args, $assoc_args ) {
		$key     = $args[0];
		$reveal  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'reveal', false );
		$context = array(
			'is_cli' => true,
			'global' => \WP_CLI\Utils\get_flag_value( $assoc_args, 'global', false ),
		);

		$manager = WP_Secrets_Manager::get_instance();

		try {
			$value = $manager->get( $key, $context );
		} catch ( WP_Secrets_Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}

		if ( null === $value ) {
			WP_CLI::error( sprintf( 'Secret "%s" not found.', $key ) );
		}

		if ( $reveal ) {
			WP_CLI::log( $value );
		} else {
			$len    = strlen( $value );
			$show   = min( 4, $len );
			$masked = substr( $value, 0, $show ) . str_repeat( '*', max( 0, $len - $show ) );
			WP_CLI::log( $masked );
		}
	}

	/**
	 * Check whether a secret exists.
	 *
	 * Exits with code 0 if the secret exists, 1 if it does not.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The secret key to check.
	 *
	 * [--global]
	 * : Allow checking unnamespaced keys.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret exists stripe/secret_key && echo "Found"
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function exists( $args, $assoc_args ) {
		$key     = $args[0];
		$context = array(
			'is_cli' => true,
			'global' => \WP_CLI\Utils\get_flag_value( $assoc_args, 'global', false ),
		);

		$manager = WP_Secrets_Manager::get_instance();
		$exists  = $manager->exists( $key, $context );

		if ( $exists ) {
			WP_CLI::success( sprintf( 'Secret "%s" exists.', $key ) );
		} else {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * List stored secret keys.
	 *
	 * Values are never displayed.
	 *
	 * ## OPTIONS
	 *
	 * [--prefix=<prefix>]
	 * : Filter keys by prefix (e.g. stripe/).
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, csv, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret list
	 *     wp secret list --prefix=stripe/
	 *     wp secret list --format=json
	 *
	 * @subcommand list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function list_( $args, $assoc_args ) {
		$prefix  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'prefix', '' );
		$format  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$context = array( 'is_cli' => true );

		$manager = WP_Secrets_Manager::get_instance();
		$keys    = $manager->list_keys( $prefix, $context );

		if ( empty( $keys ) ) {
			WP_CLI::log( 'No secrets found.' );
			return;
		}

		$items = array_map(
			function ( $key ) {
				$namespace = strstr( $key, '/', true );
				return array(
					'key'       => $key,
					'namespace' => $namespace ?: '(global)',
				);
			},
			$keys
		);

		WP_CLI\Utils\format_items( $format, $items, array( 'key', 'namespace' ) );
	}

	/**
	 * Delete a secret.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The secret key to delete.
	 *
	 * [--global]
	 * : Allow deleting unnamespaced keys.
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret delete stripe/secret_key
	 *     wp secret delete stripe/secret_key --yes
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function delete( $args, $assoc_args ) {
		$key     = $args[0];
		$context = array(
			'is_cli' => true,
			'global' => \WP_CLI\Utils\get_flag_value( $assoc_args, 'global', false ),
		);

		WP_CLI::confirm( sprintf( 'Are you sure you want to delete secret "%s"?', $key ), $assoc_args );

		$manager = WP_Secrets_Manager::get_instance();

		try {
			$result = $manager->delete( $key, $context );
		} catch ( WP_Secrets_Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}

		if ( $result ) {
			WP_CLI::success( sprintf( 'Secret "%s" deleted.', $key ) );
		} else {
			WP_CLI::warning( sprintf( 'Secret "%s" was not found or could not be deleted.', $key ) );
		}
	}

	/**
	 * Migrate secrets between providers.
	 *
	 * Reads all secrets from the source provider and writes them to the
	 * destination provider. Original values are preserved exactly.
	 *
	 * ## OPTIONS
	 *
	 * --from=<provider>
	 * : Source provider ID.
	 *
	 * --to=<provider>
	 * : Destination provider ID.
	 *
	 * [--delete-source]
	 * : Delete secrets from the source after successful migration.
	 *
	 * [--dry-run]
	 * : Show what would be migrated without making changes.
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret migrate --from=encrypted-options --to=aws-kms
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function migrate( $args, $assoc_args ) {
		$from_id = $assoc_args['from'];
		$to_id   = $assoc_args['to'];
		$dry_run = \WP_CLI\Utils\get_flag_value( $assoc_args, 'dry-run', false );
		$delete  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'delete-source', false );

		$manager       = WP_Secrets_Manager::get_instance();
		$from_provider = $manager->get_provider( $from_id );
		$to_provider   = $manager->get_provider( $to_id );

		if ( ! $from_provider ) {
			WP_CLI::error( sprintf( 'Source provider "%s" not found.', $from_id ) );
		}

		if ( ! $to_provider ) {
			WP_CLI::error( sprintf( 'Destination provider "%s" not found.', $to_id ) );
		}

		if ( ! $to_provider->is_available() ) {
			WP_CLI::error( sprintf( 'Destination provider "%s" is not available in this environment.', $to_id ) );
		}

		$context = array( 'is_cli' => true );
		$keys    = $from_provider->list_keys( '', $context );

		if ( empty( $keys ) ) {
			WP_CLI::success( 'No secrets to migrate.' );
			return;
		}

		WP_CLI::log( sprintf( 'Found %d secret(s) in "%s".', count( $keys ), $from_id ) );

		if ( $dry_run ) {
			foreach ( $keys as $key ) {
				WP_CLI::log( sprintf( '  Would migrate: %s', $key ) );
			}
			WP_CLI::success( 'Dry run complete. No changes made.' );
			return;
		}

		WP_CLI::confirm(
			sprintf( 'Migrate %d secret(s) from "%s" to "%s"?', count( $keys ), $from_id, $to_id ),
			$assoc_args
		);

		$success = 0;
		$failed  = 0;

		foreach ( $keys as $key ) {
			try {
				$value = $from_provider->get( $key, $context );
				if ( null === $value ) {
					WP_CLI::warning( sprintf( 'Could not read "%s" from source. Skipping.', $key ) );
					$failed++;
					continue;
				}

				$result = $to_provider->set( $key, $value, $context );
				if ( ! $result ) {
					WP_CLI::warning( sprintf( 'Failed to write "%s" to destination.', $key ) );
					$failed++;
					continue;
				}

				if ( $delete ) {
					$from_provider->delete( $key, $context );
				}

				$success++;
			} catch ( WP_Secrets_Exception $e ) {
				WP_CLI::warning( sprintf( 'Error migrating "%s": %s', $key, $e->getMessage() ) );
				$failed++;
			}
		}

		if ( $failed > 0 ) {
			WP_CLI::warning( sprintf( 'Migrated %d secret(s), %d failed.', $success, $failed ) );
		} else {
			WP_CLI::success( sprintf( 'Migrated %d secret(s) from "%s" to "%s".', $success, $from_id, $to_id ) );
		}
	}

	/**
	 * Re-encrypt the master key after changing WP_SECRETS_KEY.
	 *
	 * The master key architecture means only the master key needs
	 * re-encryption when you rotate WP_SECRETS_KEY — individual secrets
	 * are untouched.
	 *
	 * Before running this command:
	 *   1. Set WP_SECRETS_KEY_PREVIOUS to your old key value.
	 *   2. Set WP_SECRETS_KEY to your new key value.
	 *
	 * The provider will automatically decrypt the master key with the
	 * previous key and re-encrypt it with the new key on first access.
	 * This command forces that rotation explicitly.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret rotate
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function rotate( $args, $assoc_args ) {
		$manager  = WP_Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( ! $provider ) {
			WP_CLI::error( 'No active provider.' );
		}

		if ( ! ( $provider instanceof Provider_Encrypted_Options ) ) {
			WP_CLI::error( 'The active provider does not support master key rotation.' );
		}

		WP_CLI::confirm( 'Re-encrypt the master key with the current WP_SECRETS_KEY?', $assoc_args );

		try {
			$result = $provider->rotate_master_key();
		} catch ( WP_Secrets_Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}

		if ( $result ) {
			WP_CLI::success( 'Master key re-encrypted. You can now remove WP_SECRETS_KEY_PREVIOUS from wp-config.php.' );
		} else {
			WP_CLI::warning( 'Master key rotation returned no change (the key may already be encrypted with the current secrets key).' );
		}
	}

	/**
	 * Show active provider information.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret provider
	 *     wp secret provider --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function provider( $args, $assoc_args ) {
		$format  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$manager = WP_Secrets_Manager::get_instance();

		$providers = $manager->get_providers();
		$active_id = $manager->get_active_provider_id();

		$items = array();
		foreach ( $providers as $provider ) {
			$health  = $provider->health_check();
			$items[] = array(
				'id'        => $provider->get_id(),
				'name'      => $provider->get_name(),
				'priority'  => $provider->get_priority(),
				'available' => $provider->is_available() ? 'yes' : 'no',
				'active'    => $provider->get_id() === $active_id ? 'yes' : 'no',
				'status'    => $health['status'],
				'message'   => $health['message'],
			);
		}

		WP_CLI\Utils\format_items( $format, $items, array( 'id', 'name', 'priority', 'available', 'active', 'status', 'message' ) );
	}

	/**
	 * Export secret keys (NOT values) for documentation or audit.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, csv, json, yaml. Default: table.
	 *
	 * [--prefix=<prefix>]
	 * : Filter by key prefix.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret export-keys
	 *     wp secret export-keys --format=csv
	 *
	 * @subcommand export-keys
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function export_keys( $args, $assoc_args ) {
		$prefix  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'prefix', '' );
		$format  = \WP_CLI\Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$context = array( 'is_cli' => true );

		$manager  = WP_Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( ! $provider ) {
			WP_CLI::error( 'No active provider.' );
		}

		$keys = $provider->list_keys( $prefix, $context );

		if ( empty( $keys ) ) {
			WP_CLI::log( 'No secrets found.' );
			return;
		}

		$items = array_map(
			function ( $key ) use ( $provider ) {
				$namespace = strstr( $key, '/', true );
				return array(
					'key'       => $key,
					'namespace' => $namespace ?: '(global)',
					'provider'  => $provider->get_id(),
				);
			},
			$keys
		);

		WP_CLI\Utils\format_items( $format, $items, array( 'key', 'namespace', 'provider' ) );
	}

	/**
	 * Generate a random encryption key suitable for WP_SECRETS_KEY.
	 *
	 * ## OPTIONS
	 *
	 * [--raw]
	 * : Output only the key value without the define() wrapper.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secret generate-key
	 *     wp secret generate-key --raw
	 *
	 * @subcommand generate-key
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function generate_key( $args, $assoc_args ) {
		$raw_flag = \WP_CLI\Utils\get_flag_value( $assoc_args, 'raw', false );

		try {
			$key       = random_bytes( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
			$key_value = bin2hex( $key );
		} catch ( \Exception $e ) {
			WP_CLI::error( 'Failed to generate random key: ' . $e->getMessage() );
		}

		if ( $raw_flag ) {
			WP_CLI::log( $key_value );
		} else {
			WP_CLI::log( sprintf( "define( 'WP_SECRETS_KEY', '%s' );", $key_value ) );
			WP_CLI::log( '' );
			WP_CLI::log( 'Add the line above to your wp-config.php file.' );
		}
	}
}

WP_CLI::add_command( 'secret', 'WP_Secrets_CLI' );
