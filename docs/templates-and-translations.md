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

The bundle ships **English catalogues** for every message id it emits, in `src/Resources/translations/`: `validators.en.yaml`, `flashes.en.yaml`, `messages.en.yaml`. Symfony registers a bundle's translation directory on its own, so with `symfony/translation` installed (plus `symfony/yaml`, for the YAML loader) they apply as soon as the bundle is registered — nothing surfaces as a raw `three_brs.*` id out of the box. A unit test keeps the catalogues and the ids in `src/` in step, in both directions.

They are defaults, not fixtures:

- **Override any id** from your app's `translations/` directory — it is loaded after every bundle, so it always wins.
- A **bundle registered after this one** in `config/bundles.php` also overrides it. That is how `3brs/sylius-enterprise-security-plugin` supplies its own wording; if you register a plugin *before* this bundle, the bundle's default wins instead.
- **Other locales are yours** — the bundle ships `en` only. Add `flashes.cs.yaml`, `validators.de.yaml`, … in your app for the rest.

The tables below are the full set; the authoritative source is the message literals in `src/` (`grep -rho "three_brs\." src/`).

### Validator messages (`validators` domain)

Raised as constraint violations / form errors and rendered by the Symfony validator (which uses the `validators` domain):

| Group | Keys |
|---|---|
| Password policy | `three_brs.password_policy.`{`min_length`, `max_length`, `require_uppercase`, `require_lowercase`, `require_numbers`, `require_special_characters`} |
| Password history | `three_brs.password_history.reused` |
| Admin IP list (CIDR) | `three_brs.ip_whitelist.invalid_cidr`, `three_brs.ip_whitelist.duplicate_cidr` |
| Two-factor (setup code) | `three_brs.two_factor.invalid_code` |

The shipped `min_length` / `max_length` wording interpolates `{{ limit }}`, which the `PasswordPolicyValidatorInterface` implementation *you* provide has to set on the violation (`->setParameter('{{ limit }}', …)`); the CIDR keys interpolate `{{ value }}`, which the bundle's own validator sets.

### Flash messages

Added to the session flash bag as raw keys — the bundle does not pick a domain, so the shipped `flashes.en.yaml` assumes the conventional one (`{{ message|trans({}, 'flashes') }}`). Render them in another domain and you need the catalogue there instead:

| Group | Keys |
|---|---|
| Account deletion | `three_brs.account_deletion.`{`requested`, `cancelled`, `invalid_password`} |
| Account state (sign-in refused) | `three_brs.account_state.sign_in_refused` |
| Lockout (admin unlock) | `three_brs.lockout.unlocked`, `three_brs.lockout.already_unlocked` |
| Sessions | `three_brs.session.`{`revoked`, `others_revoked`, `cannot_revoke_current`} |
| Two-factor | `three_brs.two_factor.disabled` |
| Magic link | `three_brs.ui.magic_link.`{`request_sent`, `invalid_or_expired`} |
| Passkey | `three_brs.ui.passkey.`{`removed`, `cannot_remove_last_auth_method`} |
| Social login | `three_brs.ui.social_login.`{`linked`, `unlinked`, `already_linked`, `already_linked_other_account`, `auto_register_refused`, `cannot_unlink_last_method`, `missing_email`, `not_logged_in`, `provider_error`} |

`three_brs.ui.social_login.provider_error` covers **any** `OAuthProviderException` raised while fetching the identity on the callback — a failed token exchange, a rejected `state`, a missing authorization code, an unreadable profile response. The exception's own message is developer-facing (it can quote the provider's response body), so it goes to the logger at `warning` under `{audit channel}.provider_error` and the user sees this key.

### Surfaced elsewhere

- `three_brs.rate_limit.too_many_requests` (shipped in `flashes.en.yaml`) — the message on the `TooManyRequestsHttpException` (HTTP 429) thrown by `RateLimitGuard`; render it where you catch the exception.
- `three_brs.ui.two_factor.recovery_code_required`, `three_brs.ui.two_factor.invalid_recovery_code` (shipped in `messages.en.yaml`) — passed to the recovery-challenge template as its `error` variable, so `{{ error|trans }}` in the default domain resolves them.

> Concrete validators / flows you write yourself may add their own keys — e.g. a password-history validator that also rejects a password too similar to the current one would emit something like `three_brs.password_history.similar_to_current`, which is yours to define, not the bundle's.
