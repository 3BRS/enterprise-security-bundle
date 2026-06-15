# Centralized Security Settings

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Every feature in the bundle reads its configuration from one settings store, so behaviour (password policy, lockout thresholds, expiration days, two-factor mode, notification toggles, …) can change at runtime — no YAML edit, no container restart — and applies on the next request. The bundle ships the **store contracts and the read-side**; you provide the persistence and the admin page that writes to it.

**Bundle primitives:**
- `SettingsProviderInterface` — the read API (`getBool` / `getInt` / `getNullableInt` / `getString` / `get`, each taking a path + `SettingsScope`). You implement it (typically Doctrine-backed); see the reference impl in [Interface implementations](../interface-implementations.md#reference-impl-settings-provider-doctrine-backed).
- `SettingsWriterInterface` — the write API, needed only if you expose a runtime-mutable admin UI.
- `SettingsScope` enum — `CUSTOMER` / `ADMIN` / `GLOBAL`. The same path can hold a different value per scope (e.g. customer lockout threshold 5, admin 3); `GLOBAL` holds values with no scope dimension (2FA issuer, trusted-device window, passkey relying-party data, GeoIP service id).
- `FeatureToggle` (`FeatureToggleInterface`) — `isEnabled($feature, $scope)` reads `{feature}.enabled`; `isTwoFactorActive($scope)` treats the 2FA `mode` as the gate (2FA has no `enabled` flag).
- `PolicyFactory` (`PolicyFactoryInterface`) — assembles value objects from settings: `passwordPolicy($scope)`, `lockoutPolicy($scope)`, `twoFactorMode($scope)`.
- `YamlConfigDefaultsProvider` (+ `SettingsDefaultsBuilder`, `SettingsDefaultsProviderInterface`) — the compile-time defaults so every feature works before any row is written. See [Configuration §3](../configuration.md#3-feature-flags-compile-time-defaults).

## How a value resolves

Your `SettingsProviderInterface` impl reads the store (the recommended shape is one row per `(path, scope)` with the value stored as JSON), caches it in memory for the request, and **falls back to the YAML defaults** when a row is missing. So the bundle works out of the box, and persisting a setting is opt-in. Everything that reads settings — `PasswordExpirationChecker`, `TwoFactorEnforcementChecker`, `DynamicRateLimiterFactory`, the OAuth providers' `isEnabledForCustomer/Admin`, your `PasswordPolicyValidator`, the Twig extensions — goes through `SettingsProviderInterface` / `PolicyFactoryInterface` / `FeatureToggleInterface`, so a change takes effect on the next request.

## Runtime settings vs. compile-time parameters

Not everything belongs in the runtime store:

| Runtime settings (DB-backed, live) | Compile-time parameters (YAML / `.env`) |
|---|---|
| `password_policy.*`, `password_history.*`, `password_expiration.*` | passkey `three_brs.passkey.rp_id` / `rp_name` (bound to registered credentials — changing them invalidates existing passkeys) |
| `password_change_notification.enabled`, `login_notifications.enabled` | OAuth client credentials (`three_brs.oauth.*` — secrets; storing them in a DB would leak them via UI, dumps, audit logs) |
| `two_factor_authentication.mode` / `recovery_codes.*` | `three_brs.passkey.skip_2fa_when_user_verified` |
| `magic_link.*`, `passkey.enabled` | GeoIP provider (a DI alias resolved at compile time — see [Session management](session-management-login-notifications.md#enabling-geoip-location-lookups)) |
| `account_lockout.*`, `rate_limit.*`, `session_management.enabled` | |
| `oauth.{provider}.enabled`, `oauth.auto_register_allowed_email_domains` | |
| `ip_whitelist.*`, `ip_blacklist.*` | |

## The admin UI you build

The settings *page* is intentionally not abstracted — form layout and admin URLs vary per app. Any form that routes submitted values to `SettingsWriterInterface::write(...)` works. See [Controllers your app must provide §1](../controllers-you-provide.md#1-settings-admin-ui).

When you lay out the form, note the shape of each toggle: two-factor authentication is a **tri-state** mode (`disabled` / `allowed` / `enforced`), whereas the other auth channels (magic link, passkey, OAuth) are 2-state `enabled` toggles.
