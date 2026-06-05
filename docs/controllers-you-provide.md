# Other controllers your app must provide

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle ships **flow controllers** (login ceremonies, CSRF-protected actions) — but several pieces of a complete security UI are intentionally not abstracted because they are framework- or admin-UI-specific. You write them. The Sylius plugin has reference implementations of all of these under [`src/Controller/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Controller).

## 1. Settings admin UI

If you wire `SettingsWriterInterface` for runtime-mutable settings, you also need an admin page that renders the form, validates input, and persists. Any form solution works — the bundle only requires submitted values to reach `SettingsWriterInterface::write(...)`.

Sylius plugin reference: [`src/Controller/Admin/SecuritySettings/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Controller/Admin/SecuritySettings) (`IndexController`, `SaveController` — compound Symfony form wrapping per-tab subforms).

## 2. Admin actions targeting another user

When an admin acts on a specific user (block their account, force a password reset on next login, kill all their active sessions, kill one specific session), you write small POST handlers — each does CSRF check + repository lookup + one mutation + flash + redirect back to the user detail page. The bundle has no abstracts because admin URL structures and detail-page route names vary too much per framework.

Sylius plugin reference (5 controllers + shared base): [`src/Controller/Admin/Customer/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Controller/Admin/Customer) (`BlockAccount`, `UnblockAccount`, `ForcePasswordReset`, `RevokeAllSessions`, `RevokeSession`). The shared `AbstractCustomerSecurityActionController` handles CSRF + lookup + flash; concrete controllers only fill in the mutation.

## 3. Force-password-change UI

`PasswordExpirationChecker` flags users whose password has expired or who have `forcePasswordChange = true` on their user entity. Your app needs:

- An **event listener** (`kernel.request`) that redirects flagged users to a change-password page from anywhere they navigate to.
- The **change-password page itself**: form + handler that hashes the new password, clears the flag, invalidates the session, redirects to login.

Without this UI, the expiration flag never leads anywhere — the checker only knows the user *should* change their password, not how to make them.

Sylius plugin reference: [`src/Controller/Admin/ForcePasswordChangeController.php`](https://github.com/3BRS/sylius-enterprise-security-plugin/blob/main/src/Controller/Admin/ForcePasswordChangeController.php) (~65 lines).

## 4. IP whitelist / blacklist admin UI

The bundle ships the enforcement primitives — `CidrMatcherInterface`, the `CidrList` Symfony constraint, and the `AbstractIpRestrictionChecker` / `AbstractIpRestrictionListener` base classes that actually block a request. The admin UI to manage the lists is yours. Typical shape:

- A **list page** showing admins × their per-user whitelist (enabled flag + CIDR list).
- An **edit page** with a form (enabled toggle + CIDR list, validated by the bundle's `CidrList` constraint) that persists to your `AdminUserIpWhitelist` entity.
- A **global blacklist page** for the team-wide deny list.

Sylius plugin reference: [`IpWhitelistAdminsController.php`](https://github.com/3BRS/sylius-enterprise-security-plugin/blob/main/src/Controller/Admin/IpWhitelistAdminsController.php) (list) and [`IpWhitelistAdminEditController.php`](https://github.com/3BRS/sylius-enterprise-security-plugin/blob/main/src/Controller/Admin/IpWhitelistAdminEditController.php) (edit).

## 5. Recovery-codes one-shot display page **(critical)**

When `AbstractTwoFactorSetupController` or `AbstractTwoFactorRegenerateRecoveryCodesController` succeed, they write the **plaintext recovery codes** to session (under the key returned from `getPlainRecoveryCodesSessionKey()`) and redirect to the URL returned from `getRecoveryCodesDisplayUrl()`. That redirect target **must** be a controller you write that:

1. reads codes from session under the same key,
2. removes them from session (one-shot, never displayed again),
3. renders them so the user can write them down.

**If you forget this controller, the user never sees their recovery codes** — the codes exist only in session and the user is sent to a URL that does nothing with them. Both setup and regenerate flows depend on this display controller.

Sylius plugin reference: `src/Controller/{Admin,Shop}/TwoFactorRecoveryCodesController.php` (~44 lines each).

Skeleton:

```php
class TwoFactorRecoveryCodesController
{
    public const SESSION_KEY = 'app_plain_recovery_codes';

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected RouterInterface $router,
        protected Environment $twig,
    ) {}

    public function __invoke(Request $request): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if (!$user instanceof UserInterface) {
            return new RedirectResponse($this->router->generate('app_login'));
        }

        $session = $request->getSession();
        $codes = $session->get(self::SESSION_KEY);
        if (!is_array($codes) || $codes === []) {
            return new RedirectResponse($this->router->generate('app_dashboard'));
        }

        $session->remove(self::SESSION_KEY);

        return new Response($this->twig->render('account/two_factor/recovery_codes.html.twig', ['codes' => $codes]));
    }
}
```

Your setup + regenerate subclasses then return `TwoFactorRecoveryCodesController::SESSION_KEY` from `getPlainRecoveryCodesSessionKey()`, and `$this->router->generate('app_two_factor_recovery_codes')` from `getRecoveryCodesDisplayUrl()`.

## 6. Account-deletion anonymization cron

GDPR self-service deletion is two halves: the request/cancel flow (bundle abstract controllers) and the **batch anonymizer** that runs after the grace period. The bundle ships `AbstractDueDeletionsProcessor` (implements `DueDeletionsProcessorInterface`) which finds due requests via your `CustomerDeletionRequestRepositoryInterface` and calls your `UserAnonymizerInterface`. You provide:

- A thin **console command** (or scheduler task) that calls `DueDeletionsProcessorInterface::processDueDeletions()` on a cron.
- The `UserAnonymizerInterface` impl that clears name / email / phone / address on the user.

Sylius plugin reference: [`src/Command/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Command) and its anonymizer service under [`src/Service/`](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Service).
