# Passkey Login (WebAuthn / FIDO2)

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Passwordless sign-in with passkeys — platform authenticators (Touch ID, Windows Hello, Android lock) or hardware security keys (YubiKey). Built on `web-auth/webauthn-lib`; the bundle performs the standard WebAuthn ceremony server-side.

**What it does:**
- **Register passkeys** — runs the WebAuthn registration ceremony and persists the resulting credential against the user. A user can enrol several, each with a label (e.g. "MacBook Touch ID", "YubiKey") so they can tell them apart.
- **Passwordless login** — runs the assertion ceremony: the browser signs a challenge with a registered passkey and the bundle verifies it, then authenticates the user. No password involved.
- **Manage credentials** — list a user's passkeys and delete them; the delete flow refuses to remove the last remaining sign-in method so nobody locks themselves out.

**Bundle primitives:**
- `PasskeyValidatorFactory`, `PasskeyCeremonyStepManagerFactory`, `PasskeyRelyingPartyEntityFactory`, `PasskeyWebauthnSerializer`, `SessionPasskeyOptionsStorage` (+ interfaces) — the WebAuthn engine: build relying-party identity, generate/serialize options, store the pending ceremony in the session, validate assertions.
- `PasskeyAssertionOptionsBuilderInterface`, `PasskeyAssertionVerifierInterface`, `PasskeyAssertionResultInterface` — the assertion contracts. You implement the verifier (credential lookup + `web-auth` validation); see [Interface implementations](../interface-implementations.md#reference-impl-passkey-assertion-verifier).
- `PasskeyCredentialRecordInterface` / `PasskeyCredentialRepositoryInterface` — the per-user credential storage you implement (credential id, credential source serialized as JSON, label, sign counter, timestamps). A user can register several, each labelled (e.g. "MacBook Touch ID", "YubiKey"). See [Entities & persistence](../entities-and-persistence.md).
- `PasskeyExtension` Twig helper — `three_brs_passkey_enabled(group)` so a template renders the "Sign in with a passkey" button only when enabled.
- Flow controllers: `PasskeyLoginOptionsController` (concrete JSON endpoint) + the abstract `AbstractPasskeyLoginVerifyController`, `AbstractPasskeyRegistrationOptionsController`, `AbstractPasskeyRegistrationVerifyController`, `AbstractPasskeyListController`, `AbstractPasskeyDeleteController` — abstract methods and the full extend/register/route walkthrough are in [Controllers](../controllers.md) (the passkey login-verify flow is the worked example there).

**Behaviour:**
- **Bypasses 2FA.** `AbstractPasskeyLoginVerifyController` writes the authenticated token directly (like OAuth and magic link), so scheb's two-factor challenge is **not** triggered after a passkey sign-in. A passkey already proves possession of the registered authenticator; the second factor only guards plain password login.
- **Last-method guard.** `AbstractPasskeyDeleteController` refuses to remove a user's last remaining sign-in method.

## Front-end

The bundle is server-only. Passkey flows need browser-side `navigator.credentials.create()` / `get()` talking to the options/verify endpoints — see [Passkey front-end](../passkey-frontend.md) (the `PasskeyWebauthnSerializer` emits JSON the browser API consumes directly). Browsers without the WebAuthn API should render a hidden/disabled button rather than a broken one.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `passkey.enabled` | bool |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            passkey.enabled: false
        admin:
            passkey.enabled: false
```

## Required parameters (relying-party identity)

`rp_id` and `rp_name` are container parameters (not runtime settings) because they are bound to credentials at registration time and must stay stable. The bundle's passkey services receive them directly:

```yaml
parameters:
    three_brs.passkey.rp_id: 'example.com'                 # your domain (or `localhost` in dev)
    three_brs.passkey.rp_name: 'Example App'               # display name shown by the browser
```

Expose the login endpoints as public — the verify controller authenticates internally:

```yaml
# config/packages/security.yaml
security:
    access_control:
        - { path: ^/passkey/login/options$, role: PUBLIC_ACCESS }
        - { path: ^/passkey/login/verify$, role: PUBLIC_ACCESS }
```

> **HTTPS required.** The WebAuthn browser API only works over HTTPS or `http://localhost`. Without TLS, registration and login silently fail.
>
> **`rp_id` must match the host.** For `https://shop.example.com`, set `rp_id` to `shop.example.com` (or `example.com` to cover subdomains). A mismatch causes silent browser-side failures.
