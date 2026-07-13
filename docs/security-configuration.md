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

## Account-state checker for the sign-in controllers

The magic-link, passkey, OAuth and two-factor-recovery controllers write the token themselves, which means the firewall's user checker never runs for them. Each takes a `UserCheckerInterface` as its **last constructor argument** and calls `checkPreAuth()` before signing anyone in — otherwise an account you disabled could sign straight back in through any of those routes.

Bind a checker that refuses on the **account state alone**. It must throw `DisabledException` for an account that may not sign in, and **nothing else**:

- not `LockedException` — an account locked by failed password attempts has to keep its passwordless way in, otherwise anyone can lock a victim out of their own passkey by guessing their password wrong often enough;
- not `CredentialsExpiredException` — an expired password must not close the routes its owner needs to recover.

The bundle ships no such checker, because "enabled" is not part of Symfony's `UserInterface` — it belongs to your model. Either reuse the one your password firewall already has, or write it:

```php
// src/Security/AccountStateChecker.php
class AccountStateChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
        if ($user instanceof AppUser && ! $user->isEnabled()) {
            throw new DisabledException();
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
    }
}
```

```yaml
# config/services.yaml — pass it to every controller that extends one of the five abstracts
services:
    App\Controller\MagicLinkVerifyController:
        arguments:
            # … the bundle's other arguments
            $userChecker: '@App\Security\AccountStateChecker'
```

Translate `three_brs.account_state.sign_in_refused` — the key those controllers flash when they turn a refused account away. (The passkey verify endpoint answers `403` instead; it is consumed by a `fetch()`, not rendered.)

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
