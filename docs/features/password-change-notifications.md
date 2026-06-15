# Password Change Notifications

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Sends an email whenever a user's password changes, so the account owner is alerted to changes they did not make.

**What the bundle provides:** the feature toggle only — a `password_change_notification.enabled` setting per scope. The bundle ships **no mailer and no listener**; you wire the detection and the email in your app, gated by the toggle. (This keeps the bundle free of any mail-transport or ORM-event coupling.)

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `password_change_notification.enabled` | bool |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_change_notification.enabled: false
        admin:
            password_change_notification.enabled: false
```

## Implementing the notification

Recommended shape:

- **Detect the change at the ORM layer.** A Doctrine flush listener that inspects the password field's change set catches every flow — account settings, forgot-password reset, an admin editing another user — regardless of which controller triggered it.
- **Derive `initiatedByUser`** from the current security token: when the authenticated user *is* the user whose password changed, omit the "secure your account" link; otherwise include it (the change was made by someone else, e.g. an admin).
- **Include context** in the email: timestamp, and the client IP from `Request::getClientIp()`.
- **Gate on the toggle**: read `password_change_notification.enabled` for the affected user's scope before sending.

> **Reverse proxy / load balancer.** `Request::getClientIp()` honours `X-Forwarded-For` only for trusted proxies. Behind a load balancer or reverse proxy, configure `framework.trusted_proxies` and `framework.trusted_headers` (e.g. via `TRUSTED_PROXIES` / `TRUSTED_HEADERS`), otherwise the email logs the proxy's address instead of the real client IP. See the [Symfony docs on trusted proxies](https://symfony.com/doc/current/deployment/proxies.html).
