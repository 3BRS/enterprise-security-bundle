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
- **Timing-attack mitigation (you wire it).** The neutral body above hides *what* happened; the response *time* still gives it away, because the known-email path does a database write plus an SMTP send while the unknown one returns straight away. Pad it in your `dispatchFromForm()`: inject `TimingPaddingInterface`, take `microtime(true)` on entry, and call `padTo($startedAt)` on **every** exit path, early returns included. The default `targetSeconds = 2.0` comfortably covers the slowest happy path; tune it by decorating the `ThreeBRS\EnterpriseSecurityBundle\Timing\DeadlineTimingPadding` service.
- **Bypasses 2FA.** `AbstractMagicLinkVerifyController` writes the authenticated token directly (like OAuth and passkey), so scheb's two-factor challenge is **not** triggered after a magic-link sign-in — the second factor only guards plain password login.
- **Enforces the account state.** Writing the token outside the firewall also skips the firewall's user checker, so the controller runs it itself (`AccountStateGuardTrait`): an account disabled by an administrator — or with a self-service deletion pending — is refused here just as it is on the password form. The refusal happens **before the link is consumed** — it still works once the account is enabled again — and is answered with a flash (`three_brs.account_state.sign_in_refused`) plus a redirect back to the request page. Bind the account-state checker alone, not the whole firewall chain: an account locked by failed password attempts must keep its passwordless way in, or anyone could lock a victim out of their own passkey by guessing their password wrong often enough.

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
