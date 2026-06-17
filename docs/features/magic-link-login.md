# Magic Link Login

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Passwordless sign-in: the user submits their email and receives a single-use link that logs them in.

**Bundle primitives:**
- `MagicLinkTokenGenerator` (`MagicLinkTokenGeneratorInterface`) — `generatePlainToken()` (32 random bytes, URL-safe) and `hash()` (SHA-256). Only the **hash** is stored; the plain token exists only in the email.
- `MagicLinkTokenValidator` (`MagicLinkTokenValidatorInterface`) — single-use + expiry check (`isUsable()`).
- `MagicLinkTokenVerifierInterface` — the repository-lookup glue you provide (look up by token hash, return the record if usable). See [Interface implementations](../interface-implementations.md#reference-impl-magic-link-verifier).
- `MagicLinkRecordInterface` — the persisted token record you implement (id, user, tokenHash, expiresAt, usedAt). See [Entities & persistence](../entities-and-persistence.md). Only hashes are stored.
- `DeadlineTimingPadding` (`TimingPaddingInterface`) — see anti-enumeration below.
- `MagicLinkExtension` Twig helper — for rendering the request UI / state.
- Flow controllers (extend + bind): `AbstractMagicLinkRequestController` (renders form, dispatches the email) and `AbstractMagicLinkVerifyController` (verifies the token, authenticates, marks it used) — their abstract methods are listed in [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface), with the extend/register/route pattern in the [worked example](../controllers.md#example-passkey-login-verify-the-webauthn-assertion-endpoint).

**Hardening built into the flow:**
- **Anti-enumeration response.** The request endpoint always returns the same neutral confirmation whether the email is known, unknown, disabled or rate-limited — no account-existence leak.
- **Timing-attack mitigation.** Pad every code path to a fixed wall-clock deadline with `DeadlineTimingPadding` (default `targetSeconds = 2.0`, comfortably covering the slowest happy path — DB write + SMTP send) so response time doesn't leak existence either. Tune by decorating the `ThreeBRS\EnterpriseSecurityBundle\Timing\DeadlineTimingPadding` service with a different `$targetSeconds`.
- **Bypasses 2FA.** `AbstractMagicLinkVerifyController` writes the authenticated token directly (like OAuth and passkey), so scheb's two-factor challenge is **not** triggered after a magic-link sign-in — the second factor only guards plain password login.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `magic_link.enabled` | bool |
| `magic_link.expiration_seconds` | int |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            magic_link.enabled: false
            magic_link.expiration_seconds: 300   # 5 minutes
        admin:
            magic_link.enabled: false
            magic_link.expiration_seconds: 300
```

> **Suggested range** (validate in your settings UI — the bundle does not clamp it): `expiration_seconds` 60–3600.

> **Rate limiting** is configured separately via the `rate_limit.magic_link.*` settings (default 3 requests / 15 minutes) — see [Account Lockout & Rate Limiting](account-lockout-rate-limiting.md).

## Firewall

The verify controller authenticates internally, so both endpoints must be publicly reachable. Bind them to whatever paths you like and mark them public:

```yaml
# config/packages/security.yaml
security:
    access_control:
        - { path: ^/magic-link$, role: PUBLIC_ACCESS }
        - { path: ^/magic-link/verify/, role: PUBLIC_ACCESS }
```
