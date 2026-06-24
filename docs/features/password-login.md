# Password Login Control

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Lets you disable classic email + password sign-in for an entire scope (`customer` / `admin`), forcing everyone in that scope onto a stronger method — magic link, passkey, or a connected social account. Useful for a passwordless customer base, or an admin area that may only be entered with a passkey or social account. OAuth, passkey and magic-link sign-ins are never affected — only the password form is gated.

This is a single scope-wide policy switch, **not** a per-user flag: when it is off, *every* user in that scope is blocked from password login, regardless of which other methods they have set up.

**Bundle primitives:**
- `AbstractPasswordLoginCheckListener` — subscribes to Symfony's `CheckPassportEvent` at priority 256, i.e. **before** the password hash is verified (so a disabled login is rejected up front, with no timing side-channel on whether the password was correct). It acts only on passports carrying a `PasswordCredentials` badge, which is why OAuth / passkey / magic-link passports pass straight through. When it blocks, it throws `CustomUserMessageAuthenticationException` with your message key. You subclass it and implement three hooks:
  - `isPasswordLoginEnabled(): bool` — bind to the `password_login.enabled` toggle for the firewall's scope. Return `false` and every password login for the bound user type is rejected.
  - `isAcceptableUser(UserInterface): bool` — narrow to the user type for this firewall (customer vs admin).
  - `getErrorMessageKey(): string` — translation key shown on the login page.

There are no per-user preference contracts — the listener reads one scope-wide toggle, so there is nothing to persist per user.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type | Meaning |
|---|---|---|
| `password_login.enabled` | bool | `true` (default) — password login allowed, as normal. `false` — password login disabled for the whole scope. |

> **Note the polarity.** The toggle describes whether password login *is allowed*, so its safe default is **on** — you opt *out* of passwords by setting it to `false`. (Most other feature toggles default off; this one is the exception.)

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_login.enabled: true
        admin:
            password_login.enabled: true
```

When the toggle is on for a scope, the listener stands aside and users sign in with their password as usual. When it is off, every password login attempt for that scope is rejected at `CheckPassportEvent`.

## Scope-wide policy, no lock-out guard

Because the switch is scope-wide, turning password login off locks out every user in that scope who has no alternative sign-in method (no connected social account, no passkey, no enabled magic link). That is deliberate: it is an operator-level policy decision, so the bundle does not second-guess it with a per-user lock-out guard. Make it safe in your own admin UI instead:

- Surface the consequence where the toggle is set — it disables password sign-in for *all* accounts in the scope, not one user.
- Reflect the toggle in your sign-in and registration screens: hide or disable the password form (and password-based registration) while it is off, and point users at the methods that still work.
- Keep at least one alternative method (magic link, passkey, OAuth) enabled for the scope before turning password login off.

> **Operator note.** With password login off for a scope, password-management flows that only make sense with a password — forced password change, password expiration, "change your password" screens — no longer apply to that scope. Gate them on the same toggle in your UI so users are not pushed toward a password they can no longer use.
