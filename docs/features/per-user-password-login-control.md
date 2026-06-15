# Per-User Password Login Control

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Lets you disable classic email + password sign-in for individual users, forcing them onto a stronger method (magic link, passkey, or a connected social account). Useful for high-privilege accounts that should only sign in with a passkey, or accounts you want to migrate off passwords. OAuth, passkey and magic-link sign-ins are never affected — only the password form is gated.

**Bundle primitives:**
- `AbstractPasswordLoginCheckListener` — subscribes to Symfony's `CheckPassportEvent` at priority 256, i.e. **before** the password hash is verified (so a disabled login is rejected up front, with no timing side-channel on whether the password was correct). It acts only on passports carrying a `PasswordCredentials` badge, which is why OAuth / passkey / magic-link passports pass straight through. When it blocks, it throws `CustomUserMessageAuthenticationException` with your message key. You subclass it and implement three hooks:
  - `isFeatureEnabled(): bool` — bind to the `password_login_control.enabled` toggle for the firewall's scope.
  - `isAcceptableUser(UserInterface): bool` — narrow to the user type for this firewall.
  - `getErrorMessageKey(): string` — translation key shown on the login page.
- `PasswordLoginPreferenceInterface` / `PasswordLoginPreferenceRepositoryInterface` — the per-user switch. The listener calls `isPasswordLoginAllowedForUser($user)`; you back it with a Doctrine-persisted preference.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `password_login_control.enabled` | bool |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_login_control.enabled: false
        admin:
            password_login_control.enabled: false
```

When the feature is disabled for a scope, the listener ignores per-user preferences — every user in that scope can sign in with their password as usual.

## The per-user switch and lock-out guard

The bundle enforces the preference at login; **managing** it (the per-user toggle on a user-edit screen) is your admin UI. Implement a lock-out guard there: refuse to disable password login for a user who has no other way in (no connected social account, no passkey, and magic link not enabled for their scope), so an account can never be stripped of every sign-in method.

> **Operator note.** That guard can only run at the moment you disable password login — it is not re-checked afterwards. If a user has password login disabled and relies on a scope-toggled method (magic link, passkey, a specific OAuth provider) that you later turn off for their scope, they can be left with no way in. To recover, re-enable that method, or re-enable password login for the user.
