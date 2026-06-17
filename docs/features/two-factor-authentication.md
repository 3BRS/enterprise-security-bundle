# Two-Factor Authentication

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

TOTP-based 2FA (Google Authenticator, Authy, 1Password, …), built on top of [`scheb/2fa-bundle`](https://github.com/scheb/2fa) (pulled in automatically). The bundle adds the enrolment flow, recovery codes, and per-scope enforcement that scheb on its own leaves to you.

**What it does:**
- **Setup wizard** — enrols a user in TOTP from a QR code (or a typed-in secret), verifying a first code before switching 2FA on.
- **Recovery codes** — a set of single-use backup codes issued at setup for when the authenticator is lost; the user can regenerate them later, which invalidates the previous set.
- **Trusted device** — an optional "remember this device" cookie that skips the 2FA prompt on a known device; revocable per user by bumping `trustedTokenVersion` (which invalidates their trusted-device cookies).
- **Per-scope enforcement** — a three-state mode (`disabled` / `allowed` / `enforced`). In `enforced` mode a user who hasn't enrolled is held at the setup step until they do; `allowed` lets users opt in; `disabled` hides the feature.
- **Guards password login only.** The second factor is challenged on plain email + password sign-in; passwordless methods (OAuth, passkey, magic link) authenticate directly and bypass 2FA by design.

**Bundle primitives:**
- `TotpSecretGenerator`, `QrCodeGenerator`, `RecoveryCodeGenerator` (each with an `*Interface`) — the setup building blocks.
- `TwoFactorMode` enum — `disabled` / `allowed` / `enforced`.
- `TwoFactorEnforcementChecker` (`TwoFactorEnforcementCheckerInterface`) — `shouldEnforceForShopUser()` / `shouldEnforceForAdminUser()` return true when the scope's mode is `enforced` **and** the user has not enabled 2FA. Use it to redirect such users to setup until they enrol.
- `TwoFactorAwareAuthenticationSuccessHandler` — wraps your default success handler: if the post-login token is a scheb `TwoFactorTokenInterface` it hands off to scheb's "2FA required" handler (so the challenge UX is honoured), otherwise it delegates to the default handler. Without it, a default handler can short-circuit the 2FA challenge (e.g. redirect or return JSON straight away).
- Flow controllers (extend + bind): `AbstractTwoFactorSetupController`, `AbstractTwoFactorRecoveryChallengeController`, `AbstractTwoFactorDisableController`, `AbstractTwoFactorRegenerateRecoveryCodesController` — each one's abstract methods (its bind surface) are listed in [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface), and the extend/register/route pattern is in the [worked example](../controllers.md#example-passkey-login-verify-the-webauthn-assertion-endpoint).
- User mixin: `TwoFactorAuthShopUserInterface` / `TwoFactorAuthAdminUserInterface` (store `totpSecret`, `twoFactorEnabled`, `trustedTokenVersion`). Your entity also implements scheb's `TwoFactorInterface` for the verification hook. Trusted devices are revoked per user by bumping `trustedTokenVersion`.

> **Recovery codes are a critical handoff.** After setup/regenerate, the controllers write the plaintext codes to the session and redirect to a one-shot display page **you provide** — without it the user never sees their codes. See [Controllers your app must provide §5](../controllers-you-provide.md#5-recovery-codes-one-shot-display-page-critical).

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store):

| Path | Scope | Type |
|---|---|---|
| `two_factor_authentication.mode` | customer, admin | `disabled` \| `allowed` \| `enforced` |
| `two_factor_authentication.recovery_codes.enabled` | customer, admin | bool |
| `two_factor_authentication.recovery_codes.count` | customer, admin | int |
| `two_factor_authentication.issuer` | global | string (TOTP issuer label) |
| `two_factor_authentication.trusted_device.enabled` | global | bool |
| `two_factor_authentication.trusted_device.days` | global | int |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            two_factor_authentication.mode: 'allowed'
            two_factor_authentication.recovery_codes.enabled: true
            two_factor_authentication.recovery_codes.count: 8
        admin:
            two_factor_authentication.mode: 'enforced'
            two_factor_authentication.recovery_codes.enabled: true
            two_factor_authentication.recovery_codes.count: 8
        global:
            two_factor_authentication.issuer: 'Example App'
            two_factor_authentication.trusted_device.enabled: true
            two_factor_authentication.trusted_device.days: 60
```

> **Suggested ranges** (validate in your settings UI — the bundle does not clamp them): recovery-code `count` 1–10; trusted-device `days` 1–365. Trusted device is **scheb-wide**: scheb's JWT-cookie implementation supports a single global lifetime, so this setting is `global`, not per scope.

## scheb wiring

The `two_factor_authentication.issuer` setting is also surfaced as the `three_brs.two_factor.issuer` container parameter (see [Configuration §4](../configuration.md#4-required-scalar-parameters)) so you can reference it directly where scheb needs a compile-time value:

```yaml
# config/packages/scheb_2fa.yaml
scheb_two_factor:
    security_tokens:
        - Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken
    totp:
        enabled: true
        issuer: '%three_brs.two_factor.issuer%'
    trusted_device:
        enabled: true
        lifetime: '%env(int:THREE_BRS_2FA_TRUSTED_DEVICE_LIFETIME)%'   # seconds
        key: '%env(THREE_BRS_2FA_TRUSTED_DEVICE_KEY)%'                 # >= 256-bit secret for JWT HMAC-SHA256
```

Then, on the firewall, enable the 2FA challenge and wrap the success handler so challenges aren't skipped:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            two_factor:
                auth_form_path: app_2fa_login_form
                check_path: app_2fa_login_check
                prepare_on_login: true
                prepare_on_access_denied: true
            form_login:
                success_handler: App\Security\AppTwoFactorSuccessHandler   # instance of the bundle handler
```

Register the handler instance per firewall, wrapping scheb's required-handler and your default success handler:

```yaml
services:
    App\Security\AppTwoFactorSuccessHandler:
        class: ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorAwareAuthenticationSuccessHandler
        arguments:
            $twoFactorAuthenticationRequiredHandler: '@security.authentication.authentication_required_handler.two_factor.main'
            $defaultSuccessHandler: '@security.authentication.success_handler.main.form_login'
```

For **two firewalls**, repeat the firewall block and register a second handler instance bound to that firewall's scheb required-handler. See [Security configuration](../security-configuration.md#two-factor-authentication).
