# Account Lockout & Rate Limiting

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Brute-force protection in two layers: account-level lockout (persistent, per user) and request-level rate limiting (ephemeral, keyed per username for login and per IP for other actions). Configurable per scope (`customer` / `admin`).

## Account lockout

Locks a user account after a configurable number of consecutive failed sign-ins.

**Bundle primitives:**
- `AbstractLockoutManager` — extend it. Public API: `recordFailure($user)`, `recordSuccess($user)` (resets the counter), `isLocked($user)`, `unlock($user)`. You implement three hooks: `withPessimisticLock($user, $callback)` (serialise concurrent failures through a pessimistic row lock so the threshold can't be raced past), `commit()`, and `clearRateLimitForUser($user)` (so an unlock also clears the login rate-limit counter).
- `LockoutPolicy` (`LockoutPolicyInterface`) — `enabled` / `maxAttempts` / `autoUnlockAfter`, built by `PolicyFactory::lockoutPolicy($scope)`.
- `LockableUserInterface` (+ `LockableShopUserInterface` / `LockableAdminUserInterface` aliases) — the user-entity mixin. Four fields: `failedLoginAttempts`, `lastFailedLoginAt`, `lockedAt`, `lockoutUntil`. See [Entities & persistence](../entities-and-persistence.md).
- `LockedUserRepositoryInterface` — your lookup for the admin "locked users" list.
- Controllers: `LockedUsersListController` (concrete, render-only) and `AbstractUnlockUserController` (admin CSRF-protected unlock) — see [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface) for their bind surface and registration.

- **Auto-unlock** after `account_lockout.auto_unlock_after` seconds (`null` ⇒ manual-only). Auto-unlock fires when `lockoutUntil` is reached; an admin can also unlock manually any time — the two coexist.
- `isLocked($user)` lets your authenticator reject a locked user; the bundle ships no message of its own here, so surface it with the same generic error as a wrong password — that way lock state doesn't leak through error text.

## Rate limiting

Throttles repeated requests to sensitive endpoints so credential-stuffing and spam are slowed even when no single account crosses the lockout threshold — and, unlike lockout, it can protect actions that aren't tied to one known account (registration, password-reset and magic-link requests).

**Bundle primitives:**
- `DynamicRateLimiterFactory` (`DynamicRateLimiterFactoryInterface`) — builds Symfony `fixed_window` limiters **at runtime** from the settings (id `three_brs_{group}_{action}`), backed by the bundle's `three_brs.rate_limiter.storage`. No static `framework.yaml` limiter wiring needed (see [Configuration §1](../configuration.md#1-rate-limiter-cache-pool-auto-configured) for the cache pool).
- `RateLimitGuard` (`RateLimitGuardInterface`) — the controller-facing helper: `isEnabled($group, $action)`, `consume(Request $request, $group, $action, ?$userIdentifier)`, `reset($group, $action, $userIdentifier)`. Login limits key on the submitted username (so an admin unlock can clear them deterministically via `reset`); other actions key on `Request::getClientIp()`.

Throttled actions: `login`, `password_reset`, `register` (customer only — admin has no self-registration), `magic_link`. When a limit is exceeded, `RateLimitGuard::consume()` throws a `TooManyRequestsHttpException` (HTTP 429) carrying the `three_brs.rate_limit.too_many_requests` message key — catch it where you call the guard and surface it however suits your UI (flash + redirect, JSON error, …).

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `account_lockout.enabled` | bool |
| `account_lockout.max_attempts` | int |
| `account_lockout.auto_unlock_after` | int seconds, or `null` for manual-only |
| `rate_limit.{action}.enabled` | bool |
| `rate_limit.{action}.limit` | int |
| `rate_limit.{action}.interval` | string (e.g. `'15 minutes'`) |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            account_lockout.enabled: false
            account_lockout.max_attempts: 5
            account_lockout.auto_unlock_after: ~
            rate_limit.login.enabled: false
            rate_limit.login.limit: 5
            rate_limit.login.interval: '15 minutes'
            rate_limit.password_reset.enabled: false
            rate_limit.password_reset.limit: 3
            rate_limit.password_reset.interval: '1 hour'
            rate_limit.register.enabled: false
            rate_limit.register.limit: 5
            rate_limit.register.interval: '1 hour'
            rate_limit.magic_link.enabled: false
            rate_limit.magic_link.limit: 3
            rate_limit.magic_link.interval: '15 minutes'
        admin:
            account_lockout.enabled: false
            account_lockout.max_attempts: 3
            account_lockout.auto_unlock_after: ~
            # rate_limit.login / password_reset / magic_link — same keys as customer (no `register`)
```

> **Suggested ranges** (validate in your settings UI — the bundle does not clamp them): `max_attempts` 1–20; `auto_unlock_after` 1–86400; rate-limit `limit` 1–1000.

> **Trusted proxies.** `password_reset`, `register` and `magic_link` limits key on `Request::getClientIp()` (login keys on the username). Behind a load balancer or reverse proxy, configure `framework.trusted_proxies` and `framework.trusted_headers`, otherwise all such requests look like the proxy and the limit triggers immediately. See the [Symfony docs on trusted proxies](https://symfony.com/doc/current/deployment/proxies.html).
