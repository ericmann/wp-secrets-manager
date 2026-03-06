# WP Secrets Manager

A standardized secrets management API for WordPress. Provides `get_secret()` and `set_secret()` — the missing secrets API that WordPress has always needed. All secrets are encrypted at rest. Always.

## The Problem

Every WordPress plugin that connects to an external service stores API keys, tokens, and credentials in the `wp_options` table — in plaintext. There is no standard API for secrets management. Google Site Kit, WooCommerce, Mailchimp, Yoast, and hundreds of other plugins each reinvent their own (usually insecure) approach.

**WP Secrets Manager** solves this by providing a single, extensible API where encryption is the only option.

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

Just activate the plugin. Secrets are encrypted immediately using keys derived from your existing WordPress salts — no configuration required.

For dedicated key management, add to `wp-config.php`:

```php
// Generate with: wp secret generate-key
define( 'WP_SECRETS_KEY', 'your-generated-key-here' );
```

If you want to use an environment variable, wrap it yourself:

```php
define( 'WP_SECRETS_KEY', getenv( 'MY_SECRETS_KEY' ) );
```

## How It Works

### Architecture

WP Secrets Manager uses a three-layer architecture:

1. **Consumer Layer** — Global functions (`get_secret()`, `set_secret()`) and WP-CLI commands.
2. **SDK / Public API** — The `WP_Secrets` class that enforces access control, validates keys, fires audit hooks, and delegates to the active provider.
3. **Provider Layer** — Pluggable backends that store secrets. Ships with one built-in encrypted provider; supports third-party backends via the provider interface.

### Master Key Architecture

Secrets use a two-tier encryption scheme:

1. A **secrets key** (derived from `WP_SECRETS_KEY` or `LOGGED_IN_KEY . LOGGED_IN_SALT`) encrypts the master key.
2. A randomly-generated **master key** (stored encrypted in `wp_options`) encrypts individual secrets.

This means key rotation (`wp secret rotate`) only re-encrypts the single master key — not every stored secret.

### Key Derivation

The secrets key is derived from one of two sources:

| Priority | Source | How |
|----------|--------|-----|
| 1 | `WP_SECRETS_KEY` constant | Defined in `wp-config.php` (recommended) |
| 2 | WordPress salts | `LOGGED_IN_KEY . LOGGED_IN_SALT` (always available) |

There is no plaintext fallback. Encryption is always active.

### Automatic Provider Selection

The plugin ships with one built-in provider (encrypted options) and supports unlimited third-party providers. The highest-priority available provider is selected automatically. Power users can force a specific provider:

```php
define( 'WP_SECRETS_PROVIDER', 'aws-kms' );
```

## Key Rotation

WP Secrets Manager supports seamless key rotation via `WP_SECRETS_KEY_PREVIOUS`:

1. Set `WP_SECRETS_KEY_PREVIOUS` to your current key.
2. Set `WP_SECRETS_KEY` to your new key.
3. Run `wp secret rotate`.
4. Remove `WP_SECRETS_KEY_PREVIOUS` once done.

Because of the master key architecture, only the master key is re-encrypted — individual secrets are untouched. The provider also auto-heals: if it fails to decrypt the master key with the current key but succeeds with the previous key, it transparently re-encrypts the master key.

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

# Migrate to a different provider
wp secret migrate --from=encrypted-options --to=aws-kms

# Re-encrypt master key after key rotation
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
| `wp_secrets_master_key_rotated` | `$key_source` | When the master key is re-encrypted after rotation |
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

- **Recommended** — Using key derived from WordPress salts; suggests defining `WP_SECRETS_KEY`
- **Good** — Encrypted provider active with dedicated key
- **Good** — Third-party provider active and healthy

Debug information (key source, master key status, provider details) is available in the Site Health Info tab.

## Security Considerations

**What it protects against:**
- Database exfiltration (SQL injection, backup theft, compromised dev copies)
- Unauthorized cross-plugin access to credentials
- Accidental secret exposure in logs and admin UI

**Known limitations (documented honestly):**
- If an attacker has both database AND filesystem access (wp-config.php), local encryption is defeated. Remote providers (KMS, Vault) mitigate this.
- The `debug_backtrace()`-based caller detection is defense-in-depth, not a hard security boundary. This matches WordPress's existing trust model where plugins share a PHP process.

## Requirements

- PHP 7.2+ (sodium extension required; ships with PHP 7.2+)
- WordPress 6.9+
- WP-CLI 2.8+ (for CLI commands)

## License

GPL-2.0-or-later
