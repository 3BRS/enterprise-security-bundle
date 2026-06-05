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

Flash messages and validation errors use these Symfony translation domains:

- **flashes**: `three_brs.account_deletion.*`, `three_brs.lockout.*`, `three_brs.session.*`, `three_brs.two_factor.disabled`, `three_brs.ui.*`
- **validators**: `three_brs.two_factor.invalid_code`, etc.

Copy the keys from [the plugin's translations](https://github.com/3BRS/sylius-enterprise-security-plugin/tree/main/src/Resources/translations) and translate them. Keys with no UI value default to English fallback.
