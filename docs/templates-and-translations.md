# Templates & translations

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

## Templates

The bundle does not ship Twig templates — your app provides its own. Every abstract list / form controller has a `getTemplate(): string` method you return your template path from.

Templates the bundle controllers will render (you write them):

| Feature | Template variables passed |
|---|---|
| Sessions list | `rows: list<{session, userAgent, isCurrent}>` |
| Passkey list | `credentials: list<PasskeyCredentialInterface>` |
| Locked users list | `users: iterable<User>` |
| 2FA setup form | `form, qr_data_uri, secret` |
| 2FA manage page | `disable_csrf_token, regenerate_csrf_token, recovery_codes_enabled` |
| 2FA recovery challenge | `error: ?string` |
| Magic link request form | `form` |
| OAuth confirm link | `email, provider, error: ?string` |
| Account deletion request | `form` |

JSON API controllers (`PasskeyLoginOptions`, `PasskeyRegistrationOptions`, `PasskeyLoginVerify`, `PasskeyRegistrationVerify`) return JSON — no templates needed.

## Twig extensions

For the bits of UI that live in templates, the bundle ships three Twig extensions you can use directly (no wiring beyond registering the bundle):

- **`MagicLinkExtension`** — helpers for rendering the magic-link request UI / state.
- **`PasskeyExtension`** — helpers for the passkey management UI (e.g. exposing per-credential metadata).
- **`SocialProvidersExtension`** — enumerates the configured/enabled OAuth providers so a template can render the right "Sign in with …" buttons.

Each has a matching interface (`*Interface`) so you can decorate or replace it.

## Translation domains

The bundle ships **no translation catalogues** — any key you leave undefined renders as its raw message id (the `three_brs.*` string) to the end user, so define the ones your UI surfaces. The complete set the bundle emits is below; the authoritative source is the message literals in `src/` (`grep -rho "three_brs\." src/`).

### Validator messages (`validators` domain)

Raised as constraint violations / form errors and rendered by the Symfony validator (which uses the `validators` domain):

| Group | Keys |
|---|---|
| Password policy | `three_brs.password_policy.`{`min_length`, `max_length`, `require_uppercase`, `require_lowercase`, `require_numbers`, `require_special_characters`} |
| Password history | `three_brs.password_history.reused` |
| Admin IP list (CIDR) | `three_brs.ip_whitelist.invalid_cidr`, `three_brs.ip_whitelist.duplicate_cidr` |
| Two-factor (setup code) | `three_brs.two_factor.invalid_code` |

### Flash messages

Added to the session flash bag as raw keys (the bundle does not pick a domain — translate them when you render flashes, conventionally a `flashes` catalogue):

| Group | Keys |
|---|---|
| Account deletion | `three_brs.account_deletion.`{`requested`, `cancelled`, `invalid_password`} |
| Lockout (admin unlock) | `three_brs.lockout.unlocked`, `three_brs.lockout.already_unlocked` |
| Sessions | `three_brs.session.`{`revoked`, `others_revoked`, `cannot_revoke_current`} |
| Two-factor | `three_brs.two_factor.disabled` |
| Magic link | `three_brs.ui.magic_link.`{`request_sent`, `invalid_or_expired`} |
| Passkey | `three_brs.ui.passkey.`{`removed`, `cannot_remove_last_auth_method`} |
| Social login | `three_brs.ui.social_login.`{`linked`, `unlinked`, `already_linked`, `already_linked_other_account`, `auto_register_refused`, `cannot_unlink_last_method`, `invalid_password`, `missing_email`, `not_logged_in`} |

### Surfaced elsewhere

- `three_brs.rate_limit.too_many_requests` — the message on the `TooManyRequestsHttpException` (HTTP 429) thrown by `RateLimitGuard`; translate it where you catch/render the exception.
- `three_brs.ui.two_factor.recovery_code_required`, `three_brs.ui.two_factor.invalid_recovery_code` — passed to the recovery-challenge template as its `error` variable (you translate them in the template).

> Concrete validators / flows you write yourself may add their own keys — e.g. a password-history validator that also rejects a password too similar to the current one would emit something like `three_brs.password_history.similar_to_current`, which is yours to define, not the bundle's.
