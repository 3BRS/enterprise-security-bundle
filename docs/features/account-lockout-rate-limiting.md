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

Throttles repeated requests to sensitive endpoints, and — unlike lockout — can protect actions that aren't tied to one known account (registration, password-reset and magic-link requests). Note what the default `login` limit does **not** cover: keyed on the submitted username, it bounds guesses per account, exactly as the lockout counter does. An attacker spreading a few common passwords across many usernames stays under both and is throttled by neither; closing that needs the [per-address companion counter](#password-spraying-and-the-per-address-counter) below.

**Bundle primitives:**
- `DynamicRateLimiterFactory` (`DynamicRateLimiterFactoryInterface`) — builds Symfony `fixed_window` limiters **at runtime** from the settings (id `three_brs_{group}_{action}`), backed by the bundle's `three_brs.rate_limiter.storage`. No static `framework.yaml` limiter wiring needed (see [Configuration §1](../configuration.md#1-rate-limiter-cache-pool-auto-configured) for the cache pool).
- `RateLimitGuard` (`RateLimitGuardInterface`) — the controller-facing helper: `isEnabled($group, $action)`, `consume(Request $request, $group, $action, ?$userIdentifier)`, `reset($group, $action, $userIdentifier)`. What each counter is keyed on, and how to change it, is [below](#how-a-request-is-keyed).

Throttled actions: `login`, `password_reset`, `register` (customer only — admin has no self-registration), `magic_link`. When a limit is exceeded, `RateLimitGuard::consume()` throws a `TooManyRequestsHttpException` (HTTP 429) carrying the `three_brs.rate_limit.too_many_requests` message key — catch it where you call the guard and surface it however suits your UI (flash + redirect, JSON error, …).

### How a request is keyed

`consume()` derives the counter key from its `$userIdentifier` argument: pass one and the counter is per username (lowercased), omit it and the counter is per `Request::getClientIp()`. The bundled flows pass the username for `login` — so an admin unlock can clear that counter deterministically through `reset()` — and omit it for `password_reset`, `register` and `magic_link`, which have no known account yet.

**A counter keyed on the client IP is worth exactly what your proxy configuration is worth.** `Request::getClientIp()` returns `REMOTE_ADDR` unless `framework.trusted_proxies` is set, and behind a load balancer, an ingress controller or a CDN that is the *proxy's* address — identical for every visitor. There are two ways to get this wrong, in opposite directions:

- **Not configured.** Every request shares one apparent address, so the limiter stops being per-client and becomes global: the first `limit` requests in the window shut the endpoint for everybody, including the people you were protecting. This is worse than shipping no limiter at all.
- **Configured too widely.** Trust hops you do not actually control and `X-Forwarded-For` becomes attacker-supplied — rotating the header per request then slips past the limit entirely, while the dashboard still shows a limiter in place.

Configured correctly, header spoofing is not a concern: Symfony walks `X-Forwarded-For` from the right and returns the first address that is not a trusted proxy, so entries a client injected sit further left and are never reached.

> **Do not read a CDN header (`CF-Connecting-IP`, `True-Client-IP`, …) directly in place of `getClientIp()`.** Such a header is trustworthy *because* the chain in front of you was validated — and validating that chain is precisely what `trusted_proxies` does. Reading it yourself keeps the appearance of a client IP while dropping the check that earned it, so anyone who can reach your origin sets it freely. Symfony ships no CDN-specific header support for this reason; where a CDN forces a non-standard header, its documented answer is to normalise it into `X-Forwarded-*` yourself in `public/index.php` — at the boundary where you, and only you, know your topology.

If you cannot establish a trustworthy client IP — a shared NAT that collapses real users onto one address, an ingress whose configuration isn't yours — do not paper over it by weakening the check. Either leave the IP-keyed actions off (`rate_limit.{action}.enabled: false`), or key on a signal you *can* trust: `RateLimitGuard` is not `final` and `buildKey(Request $request, ?string $userIdentifier): string` is `protected`, so a subclass can return a hashed session id, a device fingerprint, or a header your own edge sets **and strips from inbound requests**. To replace the guard wholesale, implement `RateLimitGuardInterface` and re-alias it.

### Password spraying and the per-address counter

Keying `login` on the username bounds guesses **per account** — which is also what the lockout counter does. Neither bounds guesses **per origin**: an attacker trying three common passwords against ten thousand usernames stays under every per-account threshold and is never throttled. Spraying is built to stay under them; that is the whole technique.

If your client addresses are trustworthy (see above), close it by pairing the username-keyed action with a second one counted per address. `RateLimitGuard` takes an `$ipCompanionActions` map for this; it is empty by default, so nothing changes until you fill it in:

```yaml
# config/services.yaml — re-declare the guard to add the map
ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuard:
    arguments:
        $factory: '@ThreeBRS\EnterpriseSecurityBundle\RateLimit\DynamicRateLimiterFactory'
        $ipCompanionActions: { login: login_ip }
```

The companion is an ordinary action, so it carries its own settings — deliberately, because sharing `rate_limit.login.limit` would apply a per-account number like 5 / 15 min to an entire office behind one NAT. The bundle hard-codes no action names, so any key present in your defaults works:

```yaml
rate_limit.login_ip.enabled: true
rate_limit.login_ip.limit: 50            # generous — one address may be many people
rate_limit.login_ip.interval: '15 minutes'
```

Your call sites do not change: `consume($request, 'customer', 'login', $username)` now counts both, throwing on whichever refuses first and reporting the later of the two retry windows. Three details worth knowing:

- The companion is skipped when you pass **no** username, because the primary counter is then already keyed on the address and counting twice would halve the limit.
- The primary action's `enabled` flag gates the whole call. With `rate_limit.login.enabled: false` nothing is counted, companion included, however `rate_limit.login_ip` is set — so there is no address-only configuration: switch the companion on *alongside* the per-account limit, not instead of it.
- Both counters are consumed before either verdict is acted on, so a username that has already tripped cannot shield the address counter from accruing — which matters precisely in the spraying case.
- The two stay independent under `reset()`: `AbstractLockoutManager::unlock()` clears the username counter through `clearRateLimitForUser()`, and the address counter survives it. Unlocking one victim must not refund the attacker's budget.

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

> **Before enabling an IP-keyed action** (`password_reset`, `register`, `magic_link`, or a per-address login counter of your own), settle `framework.trusted_proxies` first — behind any proxy an unconfigured app reads one address for every visitor, and the limiter shuts the endpoint for all of them at once. See [How a request is keyed](#how-a-request-is-keyed) above and the [Symfony docs on trusted proxies](https://symfony.com/doc/current/deployment/proxies.html).
