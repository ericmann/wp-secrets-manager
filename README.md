# WP Secrets Manager

A standardized secrets management API for WordPress. Provides `get_secret()` and `set_secret()` — the missing secrets API that WordPress has always needed.

## The Problem

Every WordPress plugin that connects to an external service stores API keys, tokens, and credentials in the `wp_options` table — in plaintext. There is no standard API for secrets management. Google Site Kit, WooCommerce, Mailchimp, Yoast, and hundreds of other plugins each reinvent their own (usually insecure) approach.

**WP Secrets Manager** solves this by providing a single, extensible API with pluggable backends.

## Quick Start

### For Plugin Developers

```php
// Store a secret
set_secret( 'my-plugin/api_key', $api_key );

// Retrieve a secret
$api_key = get_secret( 'my-plugin/api_key' );

// Check existence
if ( secret_exists( 'my-plugin/api_key' ) ) {
    // ...
}

// Delete a secret
delete_secret( 'my-plugin/api_key' );
```

That's it. Encryption, key management, and backend selection are handled automatically.

### For Site Operators

Just activate the plugin. If `LOGGED_IN_KEY` and `LOGGED_IN_SALT` are defined in your `wp-config.php` (they should be — WordPress requires them), secrets are encrypted automatically with no additional configuration.

For best security, add a dedicated encryption key:

```php
// Generate with: wp secret generate-key
define( 'WP_SECRETS_KEY', 'base64:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=' );
```

## How It Works

WP Secrets Manager uses a three-layer architecture:

1. **Consumer Layer** — Global functions (`get_secret()`, `set_secret()`) and WP-CLI commands that plugins and operators interact with.
2. **SDK / Public API** — The `WP_Secrets` class that enforces access control, validates keys, fires audit hooks, and delegates to the active provider.
3. **Provider Layer** — Pluggable backends that actually store secrets. Ships with two built-in providers; supports unlimited third-party backends.

### Automatic Provider Selection

The plugin makes smart decisions so you don't have to:

| Priority | Provider | When Selected |
|----------|----------|--------------|
| 80+ | Third-party (AWS KMS, Vault, etc.) | When registered and available |
| 50 | **Encrypted Options** | When sodium + encryption key available (default on most hosts) |
| 10 | Plaintext Options | Always available — last resort fallback |

The highest-priority available provider wins. No configuration needed. Power users can force a specific provider:

```php
define( 'WP_SECRETS_PROVIDER', 'encrypted-options' );
```

## Built-in Providers

### Encrypted Options (Recommended)

Encrypts secrets with `sodium_crypto_secretbox` (XSalsa20-Poly1305) before storing in `wp_options`. Each write uses a unique nonce. The encryption key is resolved automatically:

1. `WP_SECRETS_KEY` constant in `wp-config.php` (best)
2. `WP_SECRETS_KEY` environment variable (good for containers)
3. `LOGGED_IN_KEY . LOGGED_IN_SALT` fallback (functional, ships with WordPress)

### Plaintext Options (Fallback)

Stores secrets in `wp_options` with a `_wp_secret_` prefix. Exists solely for zero-configuration environments. Site Health will recommend upgrading when this provider is active.

## Encryption Setup

### Option 1: Dedicated Key (Recommended)

```bash
# Generate a key
wp secret generate-key

# Output:
# define( 'WP_SECRETS_KEY', 'base64:abc123...=' );
#
# Add the line above to your wp-config.php file.
```

### Option 2: Environment Variable

```bash
export WP_SECRETS_KEY="base64:abc123...="
```

### Option 3: Automatic Fallback

If neither of the above is configured, the plugin derives a key from `LOGGED_IN_KEY . LOGGED_IN_SALT`. This works out of the box but is slightly less ideal because these WordPress salts can theoretically be rotated.

## Key Namespacing

Secrets use a `plugin-slug/secret-name` convention to prevent collisions:

```
woocommerce/stripe_secret_key
wp-mail-smtp/sendgrid_api_key
my-plugin/oauth_token
```

Keys without a namespace are rejected by default. Use the `--global` flag in WP-CLI for site-wide infrastructure secrets.

## WP-CLI Commands

```bash
# Store a secret
wp secret set my-plugin/api_key sk_live_abc123

# Store from stdin (avoids shell history exposure)
echo "sk_live_abc123" | wp secret set my-plugin/api_key --stdin

# Retrieve (masked by default)
wp secret get my-plugin/api_key
# Output: sk_l********************

# Retrieve with full value
wp secret get my-plugin/api_key --reveal

# Check existence (exit code 0 = exists, 1 = missing)
wp secret exists my-plugin/api_key

# List all keys (values never shown)
wp secret list
wp secret list --prefix=stripe/ --format=json

# Delete
wp secret delete my-plugin/api_key

# Show provider info
wp secret provider

# Migrate between providers
wp secret migrate --from=options --to=encrypted-options
wp secret migrate --from=encrypted-options --to=aws-kms --delete-source

# Re-encrypt after key rotation
wp secret rotate

# Export keys for documentation/audit
wp secret export-keys --format=csv

# Generate an encryption key
wp secret generate-key
```

## Access Control

The SDK enforces namespace-based access control:

1. **Own namespace** — A plugin can always read/write secrets in its own namespace (`my-plugin/*`).
2. **Cross-namespace** — Requires the `manage_secrets` capability (granted to administrators by default).
3. **CLI** — WP-CLI commands bypass namespace restrictions (shell access implies trust).

Customize access with the `wp_secrets_access` filter:

```php
add_filter( 'wp_secrets_access', function( bool $allowed, string $key, string $operation, array $context ): bool {
    // Allow a monitoring plugin to check existence of any secret
    if ( $context['plugin'] === 'my-monitor' && $operation === 'exists' ) {
        return true;
    }
    return $allowed;
}, 10, 4 );
```

## Hooks Reference

### Actions

| Hook | Parameters | Description |
|------|-----------|-------------|
| `wp_secrets_register_providers` | — | Fire to register third-party providers |
| `wp_secrets_provider_registered` | `$id, $provider` | After a provider is registered |
| `wp_secrets_provider_selected` | `$id, $method` | After the active provider is chosen |
| `wp_secrets_accessed` | `$key, $operation, $context` | Every secret operation |
| `wp_secrets_get` | `$key, $context` | After a get operation |
| `wp_secrets_set` | `$key, $context` | After a set operation (value NOT passed) |
| `wp_secrets_delete` | `$key, $context` | After a delete operation |
| `wp_secrets_exists` | `$key, $context` | After an exists check |
| `wp_secrets_list` | `$key, $context` | After a list operation |
| `wp_secrets_post_set` | `$key, $context` | After successful storage |
| `wp_secrets_post_delete` | `$key, $result, $context` | After deletion attempt |
| `wp_secrets_access_denied` | `$key, $operation, $context` | When access is denied |
| `wp_secrets_admin_page_before` | `$providers, $active_id` | Before admin page render |
| `wp_secrets_admin_page_after` | `$providers, $active_id` | After admin page render |

### Filters

| Filter | Parameters | Description |
|--------|-----------|-------------|
| `wp_secrets_provider` | `$provider_id, $key, $context` | Override which provider handles a specific key |
| `wp_secrets_pre_get` | `$value, $key, $context` | Short-circuit get (return non-null to bypass provider) |
| `wp_secrets_pre_set` | `$value, $key, $context` | Modify value before storage |
| `wp_secrets_access` | `$allowed, $key, $operation, $context` | Override access control decisions |

## Writing a Custom Provider

Third-party providers implement the `WP_Secrets_Provider` interface and register during `wp_secrets_register_providers`:

```php
<?php
/**
 * Plugin Name: WP Secrets — AWS KMS Provider
 * Requires Plugins: wp-secrets-manager
 */

add_action( 'wp_secrets_register_providers', function() {
    wp_secrets_register_provider( new My_KMS_Provider() );
});

class My_KMS_Provider implements WP_Secrets_Provider {

    public function get_id(): string {
        return 'aws-kms';
    }

    public function get_name(): string {
        return 'AWS Key Management Service';
    }

    public function get_priority(): int {
        return 80; // Higher than encrypted-options (50)
    }

    public function is_available(): bool {
        return class_exists( 'Aws\Kms\KmsClient' )
            && defined( 'WP_SECRETS_KMS_KEY_ID' );
    }

    // ... implement remaining interface methods
}
```

Use priorities above 50 for remote backends (they're inherently more secure than local encryption) and above 80 for production-grade solutions.

## Adopting WP Secrets Manager in Your Plugin

Support both secrets-managed and traditional sites:

```php
function my_plugin_get_api_key(): string {
    if ( function_exists( 'get_secret' ) ) {
        $key = get_secret( 'my-plugin/api_key' );
        if ( null !== $key ) {
            return $key;
        }
    }
    return get_option( 'my_plugin_api_key', '' );
}

function my_plugin_set_api_key( string $value ): void {
    if ( function_exists( 'set_secret' ) ) {
        set_secret( 'my-plugin/api_key', $value );
        delete_option( 'my_plugin_api_key' );
        return;
    }
    update_option( 'my_plugin_api_key', $value, false );
}
```

## Site Health Integration

WP Secrets Manager adds checks to Tools > Site Health:

- **Critical** — No encryption key available when encrypted provider is active
- **Recommended** — Using plaintext provider; suggests enabling encryption
- **Recommended** — Using fallback key instead of dedicated `WP_SECRETS_KEY`
- **Good** — Encrypted provider active with dedicated key
- **Good** — Remote provider active and healthy

Debug information is available in the Site Health Info tab.

## Security Considerations

**What it protects against:**
- Database exfiltration (SQL injection, backup theft, compromised dev copies)
- Unauthorized cross-plugin access to credentials
- Accidental secret exposure in logs and admin UI

**Known limitations (documented honestly):**
- If an attacker has both database AND filesystem access (wp-config.php), local encryption is defeated. Remote providers (KMS, Vault) mitigate this.
- The `debug_backtrace()`-based caller detection is defense-in-depth, not a hard security boundary. This matches WordPress's existing trust model where plugins share a PHP process.

## Requirements

- PHP 7.4+ (sodium extension required for encryption; ships with PHP 7.2+)
- WordPress 6.4+ (for `Requires Plugins` header support)
- WP-CLI 2.8+ (for CLI commands)

## License

GPL-2.0-or-later
