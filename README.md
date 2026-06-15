<p align="center">
    <a href="https://www.3brs.com" target="_blank">
        <img src="https://3brs1.fra1.cdn.digitaloceanspaces.com/3brs/logo/3BRS-logo-sylius-200.png"/>
    </a>
</p>
<h1 align="center">
    Enterprise Security Bundle
    <br />
    <a href="https://packagist.org/packages/3brs/enterprise-security-bundle" title="License" target="_blank">
        <img src="https://img.shields.io/packagist/l/3brs/enterprise-security-bundle.svg" />
    </a>
    <a href="https://packagist.org/packages/3brs/enterprise-security-bundle" title="Version" target="_blank">
        <img src="https://img.shields.io/packagist/v/3brs/enterprise-security-bundle.svg" />
    </a>
    <a href="https://github.com/3BRS/enterprise-security-bundle/actions" title="Build status" target="_blank">
        <img src="https://github.com/3BRS/enterprise-security-bundle/actions/workflows/ci.yml/badge.svg" />
    </a>
</h1>

A standalone Symfony bundle providing reusable security primitives — two-factor authentication, passkeys (WebAuthn/FIDO2), magic-link login, OAuth (Google, Apple, Microsoft), account lockout with rate limiting, session tracking, IP whitelist/blacklist, password policy / history / expiration, per-user password-login control, GDPR self-service account deletion, and a runtime-configurable settings store.

The bundle is framework-agnostic — drop it into any Symfony 6.4 / 7.4 app. It ships **contracts and abstract flows, not a wired-up UI** — you bind it to your app's entities, routes and templates. See the [integration guide](#integration-guide) below for how to wire it into a Symfony project.

---

## What the bundle provides

**Authentication flows** (abstract base controllers — you extend and bind to your app):
- Passkey login + registration (WebAuthn ceremony, browser-side `navigator.credentials.*`)
- Magic-link login request + verify
- OAuth login + callback + confirm-link (Google, Apple, Microsoft)
- Two-factor authentication setup wizard + recovery challenge

**Self-service actions** (abstract base controllers): session list / revoke / revoke-others · passkey list / delete · 2FA disable / regenerate recovery codes · OAuth account unlink · account deletion request (with grace period).

**Admin actions** (abstract base controllers): unlock user (after lockout) · cancel pending account deletion · locked users list.

**Security engines & services** (use directly via DI):
- **2FA:** `TotpSecretGenerator`, `QrCodeGenerator`, `RecoveryCodeGenerator`, `TwoFactorEnforcementChecker` (+ `TwoFactorMode` enum), `TwoFactorAwareAuthenticationSuccessHandler`
- **Magic link:** `MagicLinkTokenGenerator`, `MagicLinkTokenValidator`
- **Passkey:** `PasskeyValidatorFactory`, `PasskeyCeremonyStepManagerFactory`, `PasskeyRelyingPartyEntityFactory`, `PasskeyWebauthnSerializer`, `SessionPasskeyOptionsStorage`
- **OAuth:** `OAuthProviderRegistry` + Google / Apple / Microsoft providers, `AutoRegistrationPolicy`
- **Lockout & rate limiting:** `LockoutPolicy`, `RateLimitGuard`, `DynamicRateLimiterFactory`
- **Sessions:** `UserAgentParser`, `SessionFingerprintGenerator`, `GeoIpLookup` (MaxMind + Null impls)
- **Passwords:** `PasswordExpirationChecker`, `PasswordSimilarityChecker` (history), `PasswordPolicyFilteringValidator` + `PasswordPolicy` / `PasswordHistory` Symfony constraints
- **Network:** `CidrMatcher`, `CidrList` constraint, `AbstractIpRestrictionChecker` / `AbstractIpRestrictionListener` (whitelist + blacklist enforcement)
- **Per-user password-login control:** `AbstractPasswordLoginCheckListener` (forces stronger methods)
- **Account deletion (GDPR):** `GracePeriodCalculator`, `AbstractDueDeletionsProcessor` (anonymization cron engine)
- **Settings store:** `FeatureToggle`, `PolicyFactory`, `YamlConfigDefaultsProvider` (runtime-configurable, scoped CUSTOMER / ADMIN / GLOBAL)
- **Hardening:** `DeadlineTimingPadding` — constant-time response padding against account enumeration
- **Twig extensions:** `MagicLinkExtension`, `PasskeyExtension`, `SocialProvidersExtension`

**Contracts you implement** (the bundle ships interfaces; you provide Doctrine-backed impls): persisted-record contracts (`MagicLinkRecordInterface`, `SessionRecordInterface`, `SocialAccountLinkRecordInterface`, `CustomerDeletionRequestRecordInterface`, `PasskeyCredentialRecordInterface`), repository contracts, the `UserAnonymizerInterface`, and per-feature user mixins (`TwoFactorAuth*`, `Lockable*`, `PasswordExpiration*`). See [Entities & persistence](docs/entities-and-persistence.md) and [Interface implementations](docs/interface-implementations.md).

---

## Features

The bundle covers 16 security features. Each row maps the feature to the bundle primitives that power it — follow the link for the feature-level narrative, config options and defaults.

| Feature | Bundle primitives | Doc |
|---|---|---|
| Password Policy | `PasswordPolicy` constraint + `PasswordPolicyFilteringValidator` | [password-policy](docs/features/password-policy.md) |
| Password History | `PasswordHistory` constraint + `PasswordSimilarityChecker` | [password-history](docs/features/password-history.md) |
| Password Expiration | `PasswordExpirationChecker` + user mixins | [password-expiration](docs/features/password-expiration.md) |
| Password Change Notifications | `password_change_notification.enabled` settings toggle (notification is app-level) | [password-change-notifications](docs/features/password-change-notifications.md) |
| Two-Factor Authentication | TOTP / QR / recovery generators + enforcement checker + flow controllers | [two-factor-authentication](docs/features/two-factor-authentication.md) |
| 3rd-party OAuth (Social Login) | provider registry + Google/Apple/Microsoft + auto-registration policy | [oauth-social-login](docs/features/oauth-social-login.md) |
| Magic Link Login | token generator/validator + timing padding + flow controllers | [magic-link-login](docs/features/magic-link-login.md) |
| Passkey Login (WebAuthn/FIDO2) | WebAuthn serializer + validator factories + flow controllers | [passkey-login](docs/features/passkey-login.md) |
| Account Lockout & Rate Limiting | `LockoutPolicy` + `RateLimitGuard` + `DynamicRateLimiterFactory` | [account-lockout-rate-limiting](docs/features/account-lockout-rate-limiting.md) |
| Session Management & Login Notifications | session tracker + fingerprint + UA parser + GeoIP | [session-management-login-notifications](docs/features/session-management-login-notifications.md) |
| Centralized Security Settings UI | settings provider/writer contracts + feature toggle + policy factory | [centralized-security-settings-ui](docs/features/centralized-security-settings-ui.md) |
| Self-Service Account Deletion (GDPR) | grace-period calculator + due-deletions processor + anonymizer contract | [account-deletion-gdpr](docs/features/account-deletion-gdpr.md) |
| Admin IP Whitelist | `CidrMatcher` + `CidrList` constraint + IP restriction listener | [admin-ip-whitelist](docs/features/admin-ip-whitelist.md) |
| Admin IP Blacklist | same IP restriction primitives (global deny list) | [admin-ip-blacklist](docs/features/admin-ip-blacklist.md) |
| Admin Customer Management | session / lockout / password primitives | [admin-customer-management](docs/features/admin-customer-management.md) |
| Per-User Password Login Control | `AbstractPasswordLoginCheckListener` + preference contracts | [per-user-password-login-control](docs/features/per-user-password-login-control.md) |

---

## Requirements

- PHP 8.3+
- Symfony 6.4 or 7.4
- A Doctrine ORM (the bundle itself has no ORM dep, but your app needs one to persist sessions, passkey credentials, magic-link tokens, etc.)
- A user entity implementing `Symfony\Component\Security\Core\User\UserInterface`

---

## Installation

```bash
composer require 3brs/enterprise-security-bundle
```

Then register the bundle in `config/bundles.php`:

```php
return [
    // ... your existing bundles
    Scheb\TwoFactorBundle\SchebTwoFactorBundle::class => ['all' => true],
    ThreeBRS\EnterpriseSecurityBundle\ThreeBRSEnterpriseSecurityBundle::class => ['all' => true],
];
```

The bundle requires `scheb/2fa-bundle` for the 2FA flows; `composer require` pulls it in automatically.

---

## Integration guide

The bundle is contract-first: you wire each feature you want. These pages walk through it (start at the top — each builds on the previous):

| Guide | Covers |
|---|---|
| [Configuration](docs/configuration.md) | Rate-limiter cache pool, settings store, feature-flag defaults, required scalar parameters |
| [Entities & persistence](docs/entities-and-persistence.md) | User-entity mixins + the Doctrine records/repositories you provide |
| [Interface implementations](docs/interface-implementations.md) | The contracts you implement — with full reference impls (settings, magic-link, passkey) |
| [Controllers](docs/controllers.md) | Extending the abstract flow controllers + the full shipped-controller reference + security checklist |
| [Controllers your app must provide](docs/controllers-you-provide.md) | UI pieces intentionally not abstracted (settings UI, force-password-change, recovery-codes page, GDPR cron, …) |
| [Routes reference](docs/routes.md) | Every controller, its verb and a sample path |
| [Symfony security configuration](docs/security-configuration.md) | Firewall / `scheb_2fa` / OAuth provider wiring |
| [Passkey front-end](docs/passkey-frontend.md) | The browser-side WebAuthn JavaScript |
| [Templates & translations](docs/templates-and-translations.md) | Template variables, Twig extensions, translation domains |

---

## Running tests

The bundle is self-contained — clone it, install its own deps, and run the tooling directly (no Docker required):

```bash
composer install
vendor/bin/phpunit              # 326 unit tests (services + abstract controllers)
vendor/bin/phpstan analyse      # level max, generics + symfony extensions
vendor/bin/ecs check            # coding standard (--fix to apply)
```

---

## Using this bundle on Sylius

Building a [Sylius](https://sylius.com) store? You don't need to wire any of this by hand — the [ThreeBRS Enterprise Security Plugin](https://github.com/3BRS/sylius-enterprise-security-plugin) implements the ready-made Sylius UI on top of this bundle.

---

## License

MIT License. See [LICENSE](./LICENSE) for details.

## Credits

Developed by [3BRS](https://3brs.com)
