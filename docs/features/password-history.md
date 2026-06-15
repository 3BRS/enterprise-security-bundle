# Password History

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Prevents users from reusing recent passwords, and rejects trivial variations of the password they are replacing (e.g. `1234` → `12345`).

**Bundle primitives:**
- `PasswordHistory\Constraint\PasswordHistory` — the validation constraint (message `three_brs.password_history.reused`, validator id `three_brs.validator.password_history`). Attach it to the plain-password property of your change-password form/model.
- `PasswordSimilarityChecker` (`PasswordSimilarityCheckerInterface`) — substring-similarity check between two plain passwords. Catches the case a hash-by-hash lookup cannot: each stored hash is unique to its plain, so `1234` → `12345` would otherwise slip through.
- `PasswordHistoryValidatorInterface` — the contract for the constraint validator. The bundle ships the contract; you register a concrete validator under `three_brs.validator.password_history`.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin` / `global`):

| Path | Type |
|---|---|
| `password_history.enabled` | bool |
| `password_history.count` | int — how many previous passwords to remember |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_history.enabled: false
            password_history.count: 5
        admin:
            password_history.enabled: false
            password_history.count: 10
```

## Storage and the validator you provide

You own the history storage — a per-user table of past password hashes (`UserPasswordHistory` in [Entities & persistence](../entities-and-persistence.md)). Append the old hash on every password change and keep only the most recent `count` rows. If you run separate firewalls, keep a table per group.

The concrete `PasswordHistoryValidatorInterface` impl you register as `three_brs.validator.password_history` then:

1. Reads `password_history.enabled` / `password_history.count` for the user's scope.
2. Re-hashes the candidate password against each stored hash (via your password hasher) and raises `constraint->message` on a match.
3. For flows where the user submits their current password, also runs `PasswordSimilarityChecker::isSimilar(current, candidate)` and raises `three_brs.password_history.similar_to_current`.

> **Suggested range** (validate in your settings UI — the bundle does not clamp it): `count` 1–24.
