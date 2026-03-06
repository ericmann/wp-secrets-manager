<?php
/**
 * Plugin Name: WP Secrets Manager
 * Plugin URI:  https://github.com/DisplaceFoundry/wp-secrets-manager
 * Description: A standardized secrets management API for WordPress. Provides get_secret() and set_secret() with automatic encryption and a pluggable provider interface for external backends.
 * Version:     0.1.0
 * Author:      Displace Foundry
 * Author URI:  https://displacefoundry.com
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-secrets-manager
 * Requires at least: 6.4
 * Requires PHP: 7.4
 *
 * @package WP_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WP_SECRETS_MANAGER_VERSION', '0.1.0' );
define( 'WP_SECRETS_MANAGER_FILE', __FILE__ );
define( 'WP_SECRETS_MANAGER_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP_SECRETS_MANAGER_URL', plugin_dir_url( __FILE__ ) );

require_once WP_SECRETS_MANAGER_DIR . 'includes/class-wp-secrets-exception.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/interface-wp-secrets-provider.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/class-wp-secrets-context.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/class-wp-secrets-audit.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/class-wp-secrets-manager.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/class-wp-secrets.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/providers/class-provider-encrypted-options.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/admin/class-admin-page.php';
require_once WP_SECRETS_MANAGER_DIR . 'includes/admin/class-health-check.php';

/**
 * Retrieve a secret value.
 *
 * @param string $key     Namespaced secret key (e.g. 'my-plugin/api_key').
 * @param array  $context Optional. Additional context passed to the provider.
 * @return string|null The secret value, or null if not found.
 */
function get_secret( string $key, array $context = [] ): ?string {
	return WP_Secrets::get( $key, $context );
}

/**
 * Store a secret value.
 *
 * @param string $key     Namespaced secret key.
 * @param string $value   The plaintext secret value.
 * @param array  $context Optional. Additional context.
 * @return bool True on success.
 */
function set_secret( string $key, string $value, array $context = [] ): bool {
	return WP_Secrets::set( $key, $value, $context );
}

/**
 * Delete a secret.
 *
 * @param string $key     Namespaced secret key.
 * @param array  $context Optional. Additional context.
 * @return bool True on success, false if not found.
 */
function delete_secret( string $key, array $context = [] ): bool {
	return WP_Secrets::delete( $key, $context );
}

/**
 * Check whether a secret exists without retrieving its value.
 *
 * @param string $key     Namespaced secret key.
 * @param array  $context Optional. Additional context.
 * @return bool
 */
function secret_exists( string $key, array $context = [] ): bool {
	return WP_Secrets::exists( $key, $context );
}

/**
 * Register a secrets provider with the manager.
 *
 * @param WP_Secrets_Provider $provider The provider instance.
 * @return bool True if registered successfully.
 */
function wp_secrets_register_provider( WP_Secrets_Provider $provider ): bool {
	return WP_Secrets_Manager::get_instance()->register_provider( $provider );
}

/**
 * Bootstrap the plugin on the `plugins_loaded` hook to allow
 * other plugins to register providers during init.
 */
function wp_secrets_manager_init() {
	$manager = WP_Secrets_Manager::get_instance();
	$manager->register_provider( new Provider_Encrypted_Options() );

	/**
	 * Fires when providers should be registered.
	 *
	 * Third-party provider plugins hook here to register their backends.
	 */
	do_action( 'wp_secrets_register_providers' );

	$manager->select_provider();

	if ( is_admin() ) {
		new WP_Secrets_Admin_Page();
	}

	new WP_Secrets_Health_Check();
}
add_action( 'plugins_loaded', 'wp_secrets_manager_init' );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once WP_SECRETS_MANAGER_DIR . 'cli/class-wp-secrets-cli.php';
}
