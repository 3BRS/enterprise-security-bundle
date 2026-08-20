# Passkey Login (WebAuthn / FIDO2)

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Passwordless sign-in with passkeys — platform authenticators (Touch ID, Windows Hello, Android lock) or hardware security keys (YubiKey). Built on `web-auth/webauthn-lib`. The bundle ships the WebAuthn engine parts — relying-party identity pinned from configuration, ceremony step managers, option serialization, session storage for the pending ceremony — plus the HTTP endpoints around them. **The verification step itself is a hook you implement**, because it needs your credential storage; see the primitives below.

**What it does:**
- **Register passkeys** — exposes the options and verify endpoints for the registration ceremony and hands the browser's response to your `verifyAndPersist()` hook, which runs the attestation check and stores the credential. A user can enrol several, each with a label (e.g. "MacBook Touch ID", "YubiKey") so they can tell them apart.
- **Passwordless login** — exposes the options and verify endpoints for the assertion ceremony: the browser signs a challenge with a registered passkey, your `PasskeyAssertionVerifierInterface` implementation validates it against the stored credential, and the controller authenticates the user on success. No password involved.
- **Manage credentials** — list a user's passkeys and delete them, with a last-method guard the controller enforces through your `canRemoveCredential()` hook (see below).

**Bundle primitives:**
- `PasskeyValidatorFactory`, `PasskeyCeremonyStepManagerFactory`, `PasskeyRelyingPartyEntityFactory`, `PasskeyWebauthnSerializer`, `SessionPasskeyOptionsStorage` (+ interfaces) — the WebAuthn engine: build relying-party identity, generate/serialize options, store the pending ceremony in the session, validate assertions.
- `PasskeyAssertionOptionsBuilderInterface`, `PasskeyAssertionVerifierInterface`, `PasskeyAssertionResultInterface` — the assertion contracts. You implement the verifier (credential lookup + `web-auth` validation); see [Interface implementations](../interface-implementations.md#reference-impl-passkey-assertion-verifier).
- `PasskeyCredentialRecordInterface` / `PasskeyCredentialRepositoryInterface` — the per-user credential storage you implement (credential id, credential source serialized as JSON, label, sign counter, timestamps). A user can register several, each labelled (e.g. "MacBook Touch ID", "YubiKey"). See [Entities & persistence](../entities-and-persistence.md).
- `PasskeyExtension` Twig helper — `three_brs_passkey_enabled(group)` so a template renders the "Sign in with a passkey" button only when enabled.
- Flow controllers: `PasskeyLoginOptionsController` (concrete JSON endpoint) + the abstract `AbstractPasskeyLoginVerifyController`, `AbstractPasskeyRegistrationOptionsController`, `AbstractPasskeyRegistrationVerifyController`, `AbstractPasskeyListController`, `AbstractPasskeyDeleteController` — abstract methods and the full extend/register/route walkthrough are in [Controllers](../controllers.md) (the passkey login-verify flow is the worked example there).

**Behaviour:**
- **Bypasses 2FA.** `AbstractPasskeyLoginVerifyController` writes the authenticated token directly (like OAuth and magic link), so scheb's two-factor challenge is **not** triggered after a passkey sign-in. A passkey already proves possession of the registered authenticator; the second factor only guards plain password login.
- **Enforces the account state.** Writing the token outside the firewall also skips the firewall's user checker, so the controller runs it itself (`AccountStateGuardTrait`): an account disabled by an administrator — or with a self-service deletion pending — is refused here just as it is on the password form. The refusal happens **before the token is written**, and the verify endpoint answers a `403` (it is consumed by a `fetch()`, so a redirect would be of no use to the button). Bind the account-state checker alone, not the whole firewall chain: an account locked by failed password attempts must keep its passwordless way in, or anyone could lock a victim out of their own passkey by guessing their password wrong often enough.
- **Last-method guard.** Before deleting, `AbstractPasskeyDeleteController` asks your `canRemoveCredential($user)` hook; answer `false` and it flashes `three_brs.ui.passkey.cannot_remove_last_auth_method` and leaves the credential alone. Implement it against the sign-in methods your app actually offers — another passkey, a password, a linked social account — so a user can't delete their way out of their own account.

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
