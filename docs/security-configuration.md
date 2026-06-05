# Symfony security configuration

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle does not auto-configure your firewalls — you do. Minimum setup for the supported flows:

## Passkey + magic-link login

These flows write the authenticated token manually via the abstract controllers (after the WebAuthn / magic-link verification). You only need a standard firewall that recognises the token; **no custom authenticator** required:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            lazy: true
            provider: app_user_provider
            # ... your existing form_login, json_login, etc.
```

## Two-factor authentication

Install `scheb/2fa-bundle` (auto-pulled by this bundle) and configure it per its [docs](https://github.com/scheb/2fa). Minimum:

```yaml
# config/packages/scheb_2fa.yaml
scheb_two_factor:
    security_tokens:
        - Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken
    totp:
        enabled: true
        issuer: '%env(APP_NAME)%'

security:
    firewalls:
        main:
            two_factor:
                auth_form_path: app_2fa_login_form
                check_path: app_2fa_login_check
                prepare_on_login: true
                prepare_on_access_denied: true
```

Make sure your `User` entity also implements scheb's `TwoFactorInterface` from `scheb/2fa-totp` (the bundle's `TwoFactorAuthShopUserInterface` / `TwoFactorAuthAdminUserInterface` define the storage methods; scheb's interface defines the verification hook).

The bundle's `TwoFactorEnforcementChecker` (+ the `TwoFactorMode` enum: `disabled` / `allowed` / `enforced`) and `TwoFactorAwareAuthenticationSuccessHandler` drive per-group enforcement on top of scheb — wire the success handler on the firewall when you want enforcement to interrupt login until 2FA is set up.

## OAuth

OAuth itself doesn't need security.yaml changes — the bundle's `AbstractOAuthCallbackController` handles the entire flow and manually sets the security token. Just register the bundle's `GoogleOAuthProvider`, `AppleOAuthProvider` and `MicrosoftOAuthProvider` services (or your own implementations) with the `three_brs.oauth_provider` tag and the bundle's registry picks them up.
