# Password Expiration

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Forces a password change after a configurable number of days, or immediately via a per-user `forcePasswordChange` flag.

**Bundle primitives:**
- `PasswordExpirationChecker` (`PasswordExpirationCheckerInterface`) — answers `isShopUserPasswordExpired()` / `isAdminUserPasswordExpired()`. A password counts as expired when: the user's `forcePasswordChange` flag is set; **or** expiration is enabled for the scope and the reference date is older than `password_expiration.days`. The reference date is the user's `passwordChangedAt`; when that is `null` (e.g. accounts created before this feature was in place) it falls back to the account creation date (`getCreatedAt()`), so enabling expiration only forces a change on accounts already older than the window — not on everyone. A user with neither date is never expired by time alone.
- `PasswordExpirationShopUserInterface` / `PasswordExpirationAdminUserInterface` — user-entity mixins exposing `isForcePasswordChange()`, `getPasswordChangedAt()`, and `getCreatedAt()` (the expiration fallback — the account's creation timestamp, which most user entities already expose). Implement one on your user entity (see [Entities & persistence](../entities-and-persistence.md)).

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin` / `global`):

| Path | Type |
|---|---|
| `password_expiration.enabled` | bool |
| `password_expiration.days` | int |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_expiration.enabled: false
            password_expiration.days: 365
        admin:
            password_expiration.enabled: false
            password_expiration.days: 365
```

## Acting on expiration

`PasswordExpirationChecker` only reports *whether* a password is expired — it does not redirect anyone. To turn that into enforcement you provide a `kernel.request` listener that redirects flagged users to a change-password page, plus the change-password page itself (clear the flag / stamp `passwordChangedAt`, invalidate the session). See [Controllers your app must provide §3](../controllers-you-provide.md#3-force-password-change-ui). Where you send shop vs. admin users is up to your app.

> **Suggested range** (validate in your settings UI — the bundle does not clamp it): `days` 1–730.
