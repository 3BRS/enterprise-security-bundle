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

The bundle ships no such checker, because "enabled" is not part of Symfony's `UserInterface` — it belongs to your model. Write it over your own flag:

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

Translate `three_brs.account_state.sign_in_refused` — the key flashed when a refused account is turned away. Three of the five controllers use it: `AbstractMagicLinkVerifyController`, `AbstractOAuthCallbackController` and `AbstractOAuthConfirmLinkController`. The other two answer in a shape a flash would not survive, so the key never reaches the user there and you have your own wording to supply: `AbstractPasskeyLoginVerifyController` returns `403` (it is consumed by a `fetch()`, not rendered), and `AbstractTwoFactorRecoveryChallengeController` clears the token and throws `AccessDeniedException` — style that through your error page or `access_denied_handler`.

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

Wire `TwoFactorAwareAuthenticationSuccessHandler` on the firewall so your own success handler cannot short-circuit scheb's challenge for a user who has 2FA enabled.

To make `enforced` mode bite — holding users who have *not* enrolled at the setup step — add the listener from [Controllers your app must provide §7](controllers-you-provide.md#7-two-factor-enforcement-listener); the success handler does not cover that case, because scheb only issues a two-factor token for users who are already enrolled.

## OAuth

OAuth itself doesn't need security.yaml changes — the bundle's `AbstractOAuthCallbackController` handles the entire flow and manually sets the security token. Just register the bundle's `GoogleOAuthProvider`, `AppleOAuthProvider` and `MicrosoftOAuthProvider` services (or your own implementations) with the `three_brs.oauth_provider` tag and the bundle's registry picks them up.
