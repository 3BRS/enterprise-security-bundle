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
        // 1. consume pending options from session ($this->sessionStorage->consume(...))
        // 2. deserialize options + response ($this->serializer->deserialize(...)), look up credential by raw id via $this->repo
        // 3. validate via $this->validatorFactory->createAssertionValidator()->check(...)
        // 4. persist bumped sign-count + lastUsedAt, return result
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
use Psr\Log\LoggerInterface;
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
        RouterInterface $router,
        LoggerInterface $logger,
        protected PostLoginSessionTracker $sessionTracker,
        bool $enabled,
    ) {
        parent::__construct(
            $verifier, $tokenStorage, $router, $logger, $enabled,
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
            $router: '@router'
            $logger: '@logger'
            $sessionTracker: '@App\Security\Session\PostLoginSessionTracker'
            $enabled: true
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

If your app has **separate firewalls** (e.g. `shop` for customers, `admin` for staff), write **two** subclasses per feature — one per firewall — each returning its own `getFirewallName()`, route names, and templates, and register two service instances.

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

## Reference: abstract controllers and their bind surface

Each lives in `ThreeBRS\EnterpriseSecurityBundle\Controller\`. The **abstract methods** listed under each controller are exactly what your subclass implements — there is nothing else to fill in. They fall into recognisable categories:

- **Identity narrowing** (`isAcceptableUser`, `isTwoFactorCapableUser`, `isAcceptableCurrentUser`, …) — return `false` for users who must not hit this endpoint. Returning `true` blindly is an access-control bypass.
- **Persistence** (`find*ForUser`, `commit*`, `delete*`, `registerAndLink`, `linkExistingUser`, …) — your Doctrine lookups and writes, over the [record interfaces](entities-and-persistence.md) and [verifier impls](interface-implementations.md).
- **Routes / URLs** (`get*Url`, `get*Route`) — where to send the user; you pick the paths (see [Routes reference](routes.md)).
- **Firewall / log / audit** (`getFirewallName`, `getLogChannel`, `getAuditChannel`, `getAuditUserIdKey`) — per-firewall identifiers; keep them unique across firewalls.
- **Templates / forms** (`getTemplate`, `getSetupTemplate`, `create*Form`) — your Twig path / a CSRF-enabled form type.
- **Session keys** (`get*SessionKey`) — per-firewall session namespacing; keep unique across firewalls.

Every abstract controller shares the **constructor pattern** from the [worked example above](#example-passkey-login-verify-the-webauthn-assertion-endpoint): shared framework services passed to `parent::__construct`, the feature's verifier/manager service, and a `bool $enabled` that makes the flow return 404 when the feature is off. The exact dependency list is the controller's own `__construct` signature — open it, or follow the example's service definition shape.

### Authentication — passkey

- `AbstractPasskeyLoginVerifyController` — verify WebAuthn assertion, authenticate, redirect (bypasses 2FA).
  `getFirewallName`, `getDefaultRedirectUrl`, `getLogChannel`, `handlePostLogin($user, $request)`
- `AbstractPasskeyRegistrationOptionsController` — return WebAuthn creation-options JSON.
  `isAcceptableUser`, `buildRegistrationOptions($user): PublicKeyCredentialCreationOptions`
- `AbstractPasskeyRegistrationVerifyController` — verify + persist a credential.
  `isAcceptableUser`, `verifyAndPersist($user, $credentialJson, $label, $host)`, `getLogChannel`
- `AbstractPasskeyListController` — fetch + render the user's passkeys.
  `isAcceptableUser`, `findCredentialsForUser($user): iterable`, `getTemplate`
- `AbstractPasskeyDeleteController` — CSRF + lookup + last-method guard + delete.
  `getCsrfTokenId`, `isAcceptableUser`, `findCredentialForUser($id, $user): ?object`, `canRemoveCredential($user): bool`, `deleteCredential($credential)`, `getPasskeyListUrl`

### Authentication — magic link

- `AbstractMagicLinkRequestController` — render form + dispatch the email.
  `createForm`, `dispatchFromForm($form)`, `getRedirectRoute`, `getTemplate`
- `AbstractMagicLinkVerifyController` — verify the token + authenticate (bypasses 2FA).
  `isFullyAuthenticatedUser(?$token)`, `getUserFromMagicLink($record): UserInterface`, `commitMagicLinkUsage($record)`, `getFirewallName`, `getDefaultRedirectUrl`, `getMagicLinkRequestUrl`, `getLogChannel`, `handlePostLogin($user, $request)`

### Authentication — OAuth

- `AbstractOAuthInitiateController` — state-CSRF + redirect to provider.
  `isProviderEnabledForScope($provider)`, `getOAuthGroup`, `getStateSessionKey`, `getIntentSessionKey`, `getCallbackRouteName`
- `AbstractOAuthCallbackController` — fetch user info, then branch login / link / auto-register.
  `getOAuthGroup`, `getCallbackRouteName`, `getFirewallName`, `getStateSessionKey`, `getIntentSessionKey`, `getConfirmPendingSessionKey`, `getLoginRoute`, `getDashboardUrl`, `getSocialAccountsRoute`, `getConfirmLinkRoute`, `getAuditChannel`, `getAuditUserIdKey`, `isAcceptableCurrentUser(?$user)`, `findExistingLinkUser($info): ?UserInterface`, `findUserByEmail($email): ?UserInterface`, `canAutoRegister($info): bool`, `registerAndLink($info): UserInterface`, `linkExistingUser($user, $info)`, `touchLastUsed($user, $info)`, `handlePostLogin($user, $request)`
- `AbstractOAuthConfirmLinkController` — password-verify + link the existing user.
  `getConfirmPendingSessionKey`, `getFirewallName`, `getLoginRoute`, `getDashboardUrl`, `getTemplate`, `getAuditChannel`, `getAuditUserIdKey`, `findUserByEmail($email): ?UserInterface`, `findExistingLink($provider, $providerUserId): ?SocialAccountLinkRecordInterface`, `isLinkOwnedByUser($existing, $user): bool`, `linkExistingUser($user, $info)`, `handlePostLogin($user, $request)`

### Authentication — two-factor

- `AbstractTwoFactorSetupController` — TOTP + QR + recovery-code setup wizard.
  `isAcceptableUser`, `isTwoFactorAlreadyEnabled($user)`, `getUsernameForProvisioning($user)`, `createVerifyForm`, `enableTwoFactorAndPersistRecoveryCodes($user, $secret, $plainCodes)`, `getLoginUrl`, `getSetupTemplate`, `getManageTemplate`, `getRecoveryCodesDisplayUrl`, `getPendingSecretSessionKey`, `getPlainRecoveryCodesSessionKey`, `getDisableCsrfTokenId`, `getRegenerateCsrfTokenId`.
  After verification it writes the plaintext recovery codes to session under `getPlainRecoveryCodesSessionKey()` and redirects to `getRecoveryCodesDisplayUrl()` — that URL **must** point to a one-shot display controller you provide (see [Controllers your app must provide §5](controllers-you-provide.md#5-recovery-codes-one-shot-display-page-critical)).
- `AbstractTwoFactorRecoveryChallengeController` — recovery-code login completion.
  `isAcceptableUser`, `verifyAndConsumeRecoveryCode($user, $code): bool`, `getFirewallName`, `getDefaultRedirectUrl`, `getTemplate`
- `AbstractTwoFactorDisableController` — disable + invalidate codes + rotate trusted-token.
  `getCsrfTokenId`, `isTwoFactorCapableUser($user)`, `disableTwoFactorAndCommit($user)`, `getLoginUrl`, `getRedirectAfterDisableUrl`
- `AbstractTwoFactorRegenerateRecoveryCodesController` — generate + replace recovery codes.
  `getCsrfTokenId`, `isTwoFactorEnabledUser($user)`, `replaceRecoveryCodesAndCommit($user, $plainCodes)`, `getPlainRecoveryCodesSessionKey`, `getLoginUrl`, `getDashboardUrl`, `getRecoveryCodesDisplayUrl`.
  Same session handoff as setup — the redirect target is the same one-shot display controller.

### Self-service / admin actions

- `AbstractSessionsListController` — list the user's active sessions.
  `isAcceptableUser`, `findActiveSessionsForUser($user): iterable`, `getTemplate`
- `AbstractSessionRevokeController` — CSRF-protected single-session revoke.
  `isAcceptableUser`, `findSessionForUser($id, $user): ?SessionRecordInterface`, `revokeSession($session)`, `getSessionsListUrl($request)`
- `AbstractSessionRevokeOthersController` — CSRF-protected revoke-all-others.
  `isAcceptableUser`, `revokeOtherSessions($currentSessionId, $user)`, `getSessionsListUrl($request)`
- `AbstractSocialAccountUnlinkController` — CSRF + last-method guard + delete + audit.
  `getCsrfTokenId($provider)`, `isAcceptableUser`, `canUnlinkProvider($user, $provider): bool`, `deleteLinkForProvider($user, $provider): bool`, `getSocialAccountsUrl`, `getAuditChannel`, `getAuditUserIdKey`
- `AbstractUnlockUserController` — admin: CSRF + unlock a locked user.
  `getCsrfTokenId`, `getLockedListUrl`, `attemptUnlock($id): ?bool`
- `AbstractAccountDeletionRequestController` — customer: password-verify + open a grace-period request.
  `isAcceptableUser`, `hasDeletableSubject($user)`, `createDeletionRequestForm`, `dispatchDeletionRequest($user)`, `getRequestFormUrl`, `getPostDeletionUrl`, `getTemplate`
- `AbstractAccountDeletionCancelController` — admin: cancel a pending deletion.
  `cancelDeletionRequest($id): bool`, `getDeletionsListUrl`

### Concrete (no extension needed — register one or more instances per firewall with the appropriate DI arguments)
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
