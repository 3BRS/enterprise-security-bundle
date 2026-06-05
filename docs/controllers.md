# Wiring up controllers

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

This is the bundle's main extension surface. Each abstract base controller defines a security flow; you extend it with bindings for your app (user type, routes, templates, repositories).

## Example: passkey login verify (the WebAuthn assertion endpoint)

**Step 1.** Implement the verifier (Doctrine lookup + WebAuthn validation):

```php
namespace App\Security\Passkey;

use App\Entity\User;
use App\Repository\PasskeyCredentialRepository;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionVerifierInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionResultInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyValidatorFactoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\SessionPasskeyOptionsStorageInterface;

class PasskeyAssertionVerifier implements PasskeyAssertionVerifierInterface
{
    public function __construct(
        protected PasskeyValidatorFactoryInterface $validatorFactory,
        protected PasskeyWebauthnSerializerInterface $serializer,
        protected SessionPasskeyOptionsStorageInterface $sessionStorage,
        protected PasskeyCredentialRepository $repo,
    ) {}

    public function verify(string $credentialResponseJson, string $host): PasskeyAssertionResultInterface
    {
        // 1. read pending options from session
        // 2. deserialize response, look up credential by ID via $this->repo
        // 3. validate via $this->validatorFactory->build(...)
        // 4. update signCount, return result
    }
}
```

(Full body in [Interface implementations → Passkey assertion verifier](interface-implementations.md#reference-impl-passkey-assertion-verifier).)

**Step 2.** Extend the abstract base controller:

```php
namespace App\Controller;

use App\Entity\User;
use App\Security\Passkey\PasskeyAssertionVerifier;
use App\Security\Session\PostLoginSessionTracker;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyLoginVerifyController;

class PasskeyLoginVerifyController extends AbstractPasskeyLoginVerifyController
{
    public function __construct(
        PasskeyAssertionVerifier $verifier,
        TokenStorageInterface $tokenStorage,
        EventDispatcherInterface $eventDispatcher,
        AuthenticationRequiredHandlerInterface $twoFactorHandler,
        RouterInterface $router,
        LoggerInterface $logger,
        protected PostLoginSessionTracker $sessionTracker,
        bool $enabled,
        bool $skipTwoFactorWhenUserVerified,
    ) {
        parent::__construct(
            $verifier, $tokenStorage, $eventDispatcher, $twoFactorHandler,
            $router, $logger, $enabled, $skipTwoFactorWhenUserVerified,
        );
    }

    protected function getFirewallName(): string
    {
        return 'main';                   // your firewall name
    }

    protected function getDefaultRedirectUrl(): string
    {
        return $this->router->generate('app_dashboard');
    }

    protected function getLogChannel(): string
    {
        return 'app.passkey';
    }

    protected function handlePostLogin(UserInterface $user, Request $request): void
    {
        // optional: track session, send "new device" email, etc.
        if ($user instanceof User) {
            $this->sessionTracker->onLogin($user, $request);
        }
    }
}
```

**Step 3.** Register it as a service:

```yaml
services:
    App\Controller\PasskeyLoginVerifyController:
        arguments:
            $verifier: '@App\Security\Passkey\PasskeyAssertionVerifier'
            $tokenStorage: '@security.token_storage'
            $eventDispatcher: '@security.event_dispatcher.main'
            $twoFactorHandler: '@security.authentication.authentication_required_handler.two_factor.main'
            $router: '@router'
            $logger: '@logger'
            $sessionTracker: '@App\Security\Session\PostLoginSessionTracker'
            $enabled: true
            $skipTwoFactorWhenUserVerified: true
        tags:
            - { name: 'controller.service_arguments' }
```

**Step 4.** Add the route:

```yaml
# config/routes.yaml
app_passkey_login_verify:
    path: /passkey/login/verify
    controller: App\Controller\PasskeyLoginVerifyController
    methods: [POST]
```

Repeat for every flow you want enabled (typically ~15–25 controllers across all features). All abstract controllers follow the same pattern: a constructor passing shared deps to the parent + a small set of abstract methods to implement.

## Multi-firewall apps

If your app has **separate firewalls** (e.g. `shop` for customers, `admin` for staff), write **two** subclasses per feature — one per firewall — each returning its own `getFirewallName()`, route names, and templates. Register two service instances. The Sylius plugin does this throughout [`src/Controller/Shop/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Controller/Shop) and [`src/Controller/Admin/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Controller/Admin).

## Registering a concrete list controller

The list / overview controllers (`LockedUsersListController`, `AccountDeletionsListController`, `SocialAccountsOverviewController`) need no subclass — register them directly with the appropriate DI arguments and tag as a controller:

```yaml
services:
    app.controller.admin.locked_users:
        class: ThreeBRS\EnterpriseSecurityBundle\Controller\LockedUsersListController
        arguments:
            $repository: '@App\Repository\LockedUserRepository'
            $twig: '@twig'
            $template: 'admin/locked_users.html.twig'
            $enabled: '%app.lockout.enabled%'
        tags:
            - { name: 'controller.service_arguments' }

    app.controller.admin.account_deletions:
        class: ThreeBRS\EnterpriseSecurityBundle\Controller\AccountDeletionsListController
        arguments:
            $repository: '@App\Repository\CustomerDeletionRequestRepository'
            $twig: '@twig'
            $template: 'admin/pending_deletions.html.twig'
            $enabled: '%app.account_deletion.enabled%'
        tags:
            - { name: 'controller.service_arguments' }

    app.controller.shop.social_accounts:
        class: ThreeBRS\EnterpriseSecurityBundle\Controller\SocialAccountsOverviewController
        arguments:
            $twig: '@twig'
            $template: 'account/social_accounts.html.twig'
        tags:
            - { name: 'controller.service_arguments' }
```

Then reference the service IDs (not class names) in `routes.yaml`:

```yaml
app_admin_locked_users:
    path: /admin/locked-users
    controller: app.controller.admin.locked_users
    methods: [GET]
```

For multi-firewall apps register the same class twice with different repos + templates (one per firewall).

---

## Reference: abstract controllers shipped

Each lives in `ThreeBRS\EnterpriseSecurityBundle\Controller\`. Number after the name = count of abstract methods you implement.

**Authentication flows:**
- `AbstractPasskeyLoginVerifyController` (4) — verify WebAuthn assertion, authenticate, redirect (2FA-aware)
- `AbstractPasskeyRegistrationOptionsController` (2) — return WebAuthn creation options JSON
- `AbstractPasskeyRegistrationVerifyController` (3) — verify + persist credential
- `AbstractPasskeyDeleteController` (6) — CSRF + look-up + last-method guard + delete
- `AbstractPasskeyListController` (3) — fetch + render
- `AbstractMagicLinkRequestController` (4) — form + dispatch
- `AbstractMagicLinkVerifyController` (8) — verify token + authenticate (2FA-aware)
- `AbstractOAuthInitiateController` (5) — state CSRF + provider redirect
- `AbstractOAuthCallbackController` (20) — fetch user info + login or link branching
- `AbstractOAuthConfirmLinkController` (12) — password verify + link existing user
- `AbstractTwoFactorSetupController` (13) — TOTP + QR + recovery-code wizard. After verification, writes plaintext recovery codes to session under the key returned by `getPlainRecoveryCodesSessionKey()` and redirects to `getRecoveryCodesDisplayUrl()` — that URL **must** point to a one-shot display controller you provide (see [Controllers your app must provide §5](controllers-you-provide.md#5-recovery-codes-one-shot-display-page-critical)).
- `AbstractTwoFactorRecoveryChallengeController` (5) — recovery-code login completion
- `AbstractTwoFactorDisableController` (5) — disable + invalidate codes + rotate trusted-token
- `AbstractTwoFactorRegenerateRecoveryCodesController` (7) — generate + replace. Same session-handoff pattern as setup (writes to `getPlainRecoveryCodesSessionKey()`, redirects to `getRecoveryCodesDisplayUrl()`); the redirect target is the same one-shot display controller you wrote for setup.

**Self-service / admin actions:**
- `AbstractSessionRevokeController` (4)
- `AbstractSessionRevokeOthersController` (3)
- `AbstractSessionsListController` (3)
- `AbstractSocialAccountUnlinkController` (7) — CSRF + last-method guard + delete + audit
- `AbstractUnlockUserController` (3) — admin: CSRF + lockoutManager.unlock
- `AbstractAccountDeletionCancelController` (2) — admin: cancel pending deletion
- `AbstractAccountDeletionRequestController` (7) — customer: password verify + grace period

**Concrete (no extension needed — register one or more instances per firewall with the appropriate DI arguments):**
- `PasskeyLoginOptionsController` — pure JSON API; inject `PasskeyAssertionOptionsBuilderInterface` impl + `PasskeyWebauthnSerializerInterface` + `bool $enabled` (throws 404 when disabled)
- `LockedUsersListController` — render-only list; inject `LockedUserRepositoryInterface` impl + `Twig\Environment` + `string $template` + `bool $enabled` (throws 404 when disabled)
- `AccountDeletionsListController` — render-only list of pending deletion requests; inject `CustomerDeletionRequestRepositoryInterface` impl + `Twig\Environment` + `string $template` + `bool $enabled` (throws 404 when disabled)
- `SocialAccountsOverviewController` — render-only overview of the current user's linked social accounts; inject `Twig\Environment` + `string $template` (logic lives in the template, iterating `user.socialAccounts`)

---

## Security checklist when extending controllers

When you write subclasses, verify these contracts (the abstract base does the heavy lifting, but each subclass owns a few bindings):

1. **`isAcceptableUser($user)` must narrow the user type** — return false for users who shouldn't be allowed to hit this endpoint. Returning `true` blindly is an access-control bypass.
2. **`createXxxForm()` must use a CSRF-enabled form type** — Symfony forms have CSRF on by default; do not disable.
3. **`persist + flush` calls must be atomic** — don't split a logical mutation across multiple flushes (e.g. set TOTP secret AND persist recovery codes in one transaction).
4. **Session keys must be unique per firewall** — `getPendingSecretSessionKey()`, `getConfirmPendingSessionKey()`, etc. — if two firewalls share the same key, an admin user could read a customer's pending state.
5. **`getLogChannel()` and `getAuditChannel()` should be unique per firewall** — `app.passkey.shop` vs `app.passkey.admin` so log searches stay sane.
