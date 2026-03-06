=== WP Secrets Manager ===
Contributors: displacefoundry
Tags: secrets, encryption, security, api-keys, credentials
Requires at least: 6.4
Tested up to: 6.8
Stable tag: 0.1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A standardized secrets management API for WordPress. Provides get_secret() and set_secret() with automatic encryption.

== Description ==

Every WordPress plugin that connects to an external service stores API keys, tokens, and credentials in the `wp_options` table — in plaintext. There is no standard API for secrets management. WP Secrets Manager fixes this.

**WP Secrets Manager** provides `get_secret()` and `set_secret()` — the missing secrets API for WordPress. All secrets are encrypted at rest using libsodium (XSalsa20-Poly1305). It works out of the box with zero configuration.

= For Plugin Developers =

`set_secret( 'my-plugin/api_key', $api_key );`
`$api_key = get_secret( 'my-plugin/api_key' );`

That's it. Encryption and key management are handled automatically.

= For Site Operators =

Just activate. Secrets are encrypted immediately using keys derived from your existing WordPress salts. For better key management, add a dedicated key to `wp-config.php`:

`define( 'WP_SECRETS_KEY', 'base64:XXXXXXXXXXXXXXXX...' );`

Generate one with `wp secret generate-key`.

= Key Features =

* **Always encrypted** — No plaintext fallback. Secrets are encrypted at rest using `sodium_crypto_secretbox`.
* **Zero configuration** — Works immediately using WordPress salts as key material. No setup required.
* **Master key architecture** — Individual secrets are encrypted with a master key, which is itself encrypted with WP_SECRETS_KEY. Key rotation only re-encrypts the master key, not every secret.
* **WP_SECRETS_KEY_PREVIOUS** — Seamless key rotation without downtime.
* **WP-CLI integration** — Full `wp secret` command family for managing secrets from the terminal.
* **Namespace-based access control** — Plugins can only read their own secrets by default.
* **Extensible provider interface** — Ready for third-party backends (AWS KMS, Vault, etc.) via separate plugins.
* **Audit hooks** — Every operation fires WordPress actions for integration with audit log plugins.
* **Site Health integration** — Reports encryption status and key source in Tools > Site Health.

= WP-CLI Commands =

* `wp secret set <key> <value>` — Store a secret
* `wp secret get <key>` — Retrieve a secret (masked by default)
* `wp secret exists <key>` — Check if a secret exists
* `wp secret list` — List all secret keys
* `wp secret delete <key>` — Delete a secret
* `wp secret rotate` — Re-encrypt master key after key rotation
* `wp secret provider` — Show provider information
* `wp secret generate-key` — Generate a WP_SECRETS_KEY value
* `wp secret export-keys` — Export key names for audit

== Installation ==

1. Upload the `wp-secrets-manager` directory to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. (Optional) Add a dedicated encryption key to `wp-config.php`:

`define( 'WP_SECRETS_KEY', 'base64:...' );`

Generate one with: `wp secret generate-key`

== Frequently Asked Questions ==

= Do I need to configure anything? =

No. The plugin works immediately after activation. It derives encryption keys from your existing WordPress salts (`LOGGED_IN_KEY` and `LOGGED_IN_SALT`).

For better security, you can define a dedicated `WP_SECRETS_KEY` in `wp-config.php`, but this is optional.

= What happens when I rotate WP_SECRETS_KEY? =

1. Set `WP_SECRETS_KEY_PREVIOUS` to your old key.
2. Set `WP_SECRETS_KEY` to your new key.
3. Run `wp secret rotate` to re-encrypt the master key.
4. Remove `WP_SECRETS_KEY_PREVIOUS` once complete.

Because of the master key architecture, only the master key is re-encrypted — not every individual secret.

= Can plugins read each other's secrets? =

Not by default. Each plugin can only access secrets in its own namespace (`plugin-slug/*`). Cross-namespace access requires the `manage_secrets` capability.

= Are secret values ever displayed in the admin UI? =

Never. The admin page shows only key names, never values. The WP-CLI `get` command masks values by default and requires `--reveal` to display them.

= Can I use external backends like AWS KMS or HashiCorp Vault? =

The provider interface is designed for this. Third-party provider plugins can register during the `wp_secrets_register_providers` action. First-party provider plugins are planned.

== Changelog ==

= 0.1.0 =
* Initial release.
* Encrypted options provider with sodium_crypto_secretbox.
* Master key architecture for efficient key rotation.
* WP_SECRETS_KEY and WP_SECRETS_KEY_PREVIOUS support.
* WP-CLI integration with full `wp secret` command family.
* Namespace-based access control.
* Audit logging via WordPress actions.
* Site Health integration.
* Admin overview page under Tools > Secrets.
