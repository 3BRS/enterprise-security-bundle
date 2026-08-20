# 3rd-party OAuth (Social Login)

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Sign in (and optionally auto-register) with **Google, Apple and Microsoft** — for the customer scope, the admin scope, or both, each configured independently so you can use separate OAuth clients per scope. The provider registry is extensible: add GitHub, LinkedIn, … without touching routing, controllers or templates.

**What it does:**
- **Social sign-in** — drives the OAuth redirect/callback, fetches the user's profile, and signs them in. The exact outcome depends on what's found for the identity's email (see [the three callback outcomes](#the-three-callback-outcomes) below).
- **Account linking** — connects a social identity to an existing account (after confirming ownership of that account, to prevent takeover); a user can link several providers and **unlink** them from their account page (behind a last-method guard whose decision you supply — see below).
- **Auto-registration** — for an unknown email, optionally creates a new account, gated by `AutoRegistrationPolicy` (any email the provider didn't mark unverified, a domain whitelist, or off).
- **Enforces the account state** — an account disabled by an administrator (or with a self-service deletion pending) is refused on the callback and on the confirm-link step, before the social link it was about to create is created. The token is written outside the firewall (so 2FA, which guards password sign-in, is not challenged), which means the firewall's user checker never runs — the controllers run the account-state checker themselves (`AccountStateGuardTrait`).
- **Pluggable providers** — Google / Apple / Microsoft ship in the bundle; anything implementing `OAuthProviderInterface` and tagged for the registry joins the login buttons automatically.
- **Cross-site `form_post` providers** — some providers (e.g. Apple) return the callback as a cross-site `POST`, so the browser withholds the `SameSite=Lax` session cookie and the OAuth `state` would be lost. Mark such a provider with `FormPostOAuthProviderInterface` and the controllers carry the `state` (and, for a link, the initiating user) in a dedicated `SameSite=None; Secure; HttpOnly`, **HMAC-signed** single-use cookie (signed by `StateCookieSigner`, keyed on `%kernel.secret%`) that is validated and cleared on the callback — the signature makes the cookie's contents tamper-proof, so a client can't forge the `state` or the link user, and there's no need to weaken the application's session cookie. (`Secure` ⇒ HTTPS, which such providers require anyway.) The signature also carries its own expiry (`StateCookieSigner`'s `$ttl`, 600 s by default), so a copy of the value that outlives the browser stops working on its own.

**Bundle primitives:**
- `OAuthProviderRegistry` (`OAuthProviderRegistryInterface`) — collects every service tagged `three_brs.oauth_provider`. The login controllers and the `SocialProvidersExtension` Twig helper read the registry, so adding a provider needs no controller/route/template changes.
- `GoogleOAuthProvider`, `AppleOAuthProvider`, `MicrosoftOAuthProvider` (+ interfaces) — ship in the bundle. Apple's ES256 `client_secret` JWT is generated at runtime from team id / key id / `.p8` private key; Microsoft uses the Identity Platform v2.0 endpoint with a configurable `tenant`.
- `OAuthProviderInterface` — implement it for a new provider: `getName()`, `isEnabledForCustomer()`, `isEnabledForAdmin()`, `getAuthorizationUrl($redirectUri, $state, $group)`, `fetchUserInfo($request, $redirectUri, $expectedState, $group)` (returns an `OAuthUserInfoInterface`: provider name, provider user id, email, first/last name, email-verified flag). `$group` is `customer` or `admin`.
- `AutoRegistrationPolicy` (`AutoRegistrationPolicyInterface`) — `canAutoRegister($info, ?array $allowedEmailDomains)`. Requires a non-empty email that the provider did not report as **explicitly unverified**, then: `null` ⇒ allow any such email; `[]` ⇒ deny (auto-registration off); a list ⇒ allow only those email domains.
  > **What "verified" means, per provider.** The policy rejects an email the provider marked unverified and accepts one it says nothing about — most providers emit no such claim, and treating silence as failure would switch auto-registration off for them entirely. Check what yours actually attests before enabling it:
  >
  > | Provider | Attests the address? | Auto-registration |
  > |---|---|---|
  > | Google | Yes — sends `email_verified`, which the policy enforces. | Safe. |
  > | Apple | Yes on every sign-in — except managed Apple School Manager accounts, whose token may carry no address, in which case the library falls back to one taken from the request. | Safe, unless you serve School Manager accounts. |
  > | Microsoft | No — Entra emits no such claim, and Microsoft's own guidance is never to use `email` for authorization. | Needs care — see [Auto-registration safety](#settings). |
  >
  > None of this puts an **existing** account at risk: a matching email always goes to the outcome-2 ownership challenge, never straight to a sign-in. It only matters where an unattested address is trusted on its own, which is auto-registration.
- `OAuthLinkCodeGenerator` (`OAuthLinkCodeGeneratorInterface`) — optional helper for the confirm-link challenge: generates and SHA-256-hashes a zero-padded 6-digit one-time code, for subclasses that prove account ownership by emailing a code. Its verify counterpart is `CodeChallengeValidator` (below).
- `CodeChallengeValidator` (`CodeChallengeValidatorInterface`) — the **verify half** of a one-time-code challenge, so integrators don't re-implement it. Given the stored challenge state (`CodeChallengeState`: code hash, expiry, attempt count) and the submitted code's hash, it enforces **expiry + attempt limit + single-use + constant-time compare** and returns a `CodeChallengeOutcome`: the verdict (accepted / expired / too-many-attempts / invalid) plus the next state to persist (attempt incremented, or the code burned). Clock-driven and transport-agnostic — it never touches the session, so you choose where the state lives. Mirrors `MagicLinkTokenValidator`, with the added guess counter a short code needs.
- `SocialAccountLinkRecordInterface` — the persisted link record you implement (see [Entities & persistence](../entities-and-persistence.md)); a user can have several.
- `SocialProvidersExtension` Twig helper — enumerates enabled providers so a template renders the right "Sign in with …" buttons.
- Flow controllers (extend + bind): `AbstractOAuthInitiateController`, `AbstractOAuthCallbackController`, `AbstractOAuthConfirmLinkController`, `AbstractSocialAccountUnlinkController`; plus the render-only `SocialAccountsOverviewController`. Their abstract methods (the bind surface — `findUserByEmail`, `registerAndLink`, `linkExistingUser`, …) are listed in [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface).

## The three callback outcomes

`AbstractOAuthCallbackController` branches on what it finds for the OAuth identity's email:

1. **Already linked** → straight log-in.
2. **Email matches a local account** → an ownership-proof challenge (`AbstractOAuthConfirmLinkController`) before the link is created — prevents account takeover. The proof is pluggable via the controller's `prepareChallenge()` / `verifyChallenge()` hooks (e.g. a one-time code emailed to the account — `OAuthLinkCodeGenerator` mints it and `CodeChallengeValidator` runs the verify, so you don't re-implement expiry / attempt-limit / single-use).
3. **Unknown email** → `AutoRegistrationPolicy` decides whether to auto-create the account and link the identity.

Outcome 1 is keyed on the **identity**, outcomes 2 and 3 on the email. Implement `findExistingLinkUser($info)` accordingly: look the link up by the `(getProvider(), getProviderUserId())` pair — the provider's immutable subject id, which is what `getProviderUserId()` returns — and never by `getEmail()`. Outcome 1 signs the user straight in, so keying it on the email would let a forged claim skip the outcome-2 ownership challenge entirely.

The unlink action carries a last-method guard: `AbstractSocialAccountUnlinkController` asks your `canUnlinkProvider($user, $provider)` hook first and, on `false`, flashes `three_brs.ui.social_login.cannot_unlink_last_method` and keeps the link. Implement it against the sign-in methods your app offers — a password, a passkey, another provider — so a user can't unlink themselves out of their own account.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin`):

| Path | Type |
|---|---|
| `oauth.google.enabled` | bool |
| `oauth.apple.enabled` | bool |
| `oauth.microsoft.enabled` | bool |
| `oauth.auto_register_allowed_email_domains` | list of strings (passed to `AutoRegistrationPolicy`) |

A provider only reports `isEnabledForCustomer()` / `isEnabledForAdmin()` true when **both** its `enabled` setting is on **and** its credentials (below) are present for that scope.

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            oauth.google.enabled: false
            oauth.apple.enabled: false
            oauth.microsoft.enabled: false
            oauth.auto_register_allowed_email_domains: []
        admin:
            oauth.google.enabled: false
            oauth.apple.enabled: false
            oauth.microsoft.enabled: false
            oauth.auto_register_allowed_email_domains: []
```

> **Auto-registration safety.** Pass `null` for "any email may register" (commercial signups), `[]` to disable it, or a domain list to restrict it. For the **admin** scope, only ever whitelist domains you fully control — anyone with a working email in a listed domain could self-create a privileged account. Creating the account (roles, locale, …) happens in your `AbstractOAuthCallbackController` subclass, not in the bundle.
>
> **On Microsoft, a domain list is not proof of domain ownership.** It filters an email claim Entra never attested, and with `tenant: 'common'` (or `organizations`) that claim can come from any tenant, including one the attacker registered. Either pin `tenant` to your own tenant id, enable the `xms_edov` optional claim and require it to be `true`, or leave auto-registration off and verify the address yourself before provisioning.

## Credentials (deployment parameters)

Client credentials are container parameters injected into the provider services — not runtime settings. Define them per scope as `three_brs.oauth.{customer|admin}.{provider}.{key}` (see [Configuration §4](../configuration.md#4-required-scalar-parameters)). Required keys per provider:

| Provider | Keys |
|---|---|
| Google | `client_id`, `client_secret` |
| Apple | `client_id` (the Services ID), `team_id`, `key_id`, `private_key_path` (path to the `.p8`) |
| Microsoft | `client_id`, `client_secret`, `tenant` (`common` / `organizations` / a tenant GUID) |

```yaml
parameters:
    three_brs.oauth.customer.google.client_id: '%env(GOOGLE_CLIENT_ID)%'
    three_brs.oauth.customer.google.client_secret: '%env(GOOGLE_CLIENT_SECRET)%'
    three_brs.oauth.customer.microsoft.client_id: '%env(MICROSOFT_CLIENT_ID)%'
    three_brs.oauth.customer.microsoft.client_secret: '%env(MICROSOFT_CLIENT_SECRET)%'
    three_brs.oauth.customer.microsoft.tenant: 'common'
    # … apple keys if used; admin.* variants if you run a separate admin firewall
```

Callback URL to register with each provider matches the path you bind `AbstractOAuthCallbackController` to — e.g. `https://<your-domain>/oauth/{provider}/callback` (and a second path if you run a separate admin firewall).

---

## Google Cloud setup

1. Open the [Google Cloud Console](https://console.cloud.google.com/) and create (or select) a project.
2. **APIs & Services → OAuth consent screen** — choose *External*, fill in app name, support email and developer contact. Add scopes `openid`, `email`, `profile`. Add test users while in *Testing* mode.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**:
   - Application type: *Web application*
   - Authorized JavaScript origins: `https://<your-domain>`
   - Authorized redirect URIs: your callback path(s), e.g. `https://<your-domain>/oauth/google/callback`
4. Copy the **Client ID** / **Client secret** into the env vars wired to `three_brs.oauth.*.google.*`.
5. Set `oauth.google.enabled: true` for the relevant scope (see [Settings](#settings)).

## Apple Developer setup

Apple Sign In requires a paid Apple Developer account and a **public HTTPS** redirect URL (`http://localhost` is rejected — tunnel over HTTPS for local testing).

1. In the [Apple Developer portal](https://developer.apple.com/account/resources/) → **Certificates, Identifiers & Profiles**:
   - **Identifiers → App IDs** — create an App ID with *Sign In with Apple* enabled.
   - **Identifiers → Services IDs** — create a Services ID (this is the `client_id`), enable *Sign In with Apple*, and add your return URL (your callback path).
   - **Keys** — create a key with *Sign In with Apple*, download the `.p8` (downloadable once), note the **Key ID**.
2. Find your **Team ID** under *Membership*.
3. Store the `.p8` outside version control and point `three_brs.oauth.*.apple.private_key_path` at it; set `client_id`, `team_id`, `key_id`.
4. Set `oauth.apple.enabled: true` for the scope. The bundle's `AppleOAuthProvider` generates the ES256 `client_secret` JWT at runtime — no long-lived secret to store.

## Microsoft Entra ID setup

Microsoft uses the Identity Platform v2.0 endpoint. `tenant: common` accepts any Microsoft account (personal or work/school); use `organizations` for work/school only, or a tenant GUID for a single organization.

> **Pick the narrowest `tenant` you can.** `common` and `organizations` accept sign-ins from every Entra tenant, which makes the `email` claim attacker-controllable; your own tenant GUID does not. It only matters if you auto-register — see [Auto-registration safety](#settings). The `oid` used as the identity key is safe on any `tenant` value.

1. [Microsoft Entra admin center](https://entra.microsoft.com/) → **App registrations → New registration**: pick the *Supported account types* matching your intended `tenant`, and set the **Redirect URI** (*Web*) to your callback path.
2. **Certificates & secrets → New client secret** — copy the *Value* immediately.
3. **API permissions → Microsoft Graph → Delegated** — ensure `openid`, `profile`, `email`, `User.Read` (the default set).
4. Wire `client_id`, `client_secret` and `tenant` to `three_brs.oauth.*.microsoft.*`, then set `oauth.microsoft.enabled: true` for the scope.

> **Suggested limit** for `oauth.auto_register_allowed_email_domains` (validate in your settings UI — the bundle does not clamp it): at most 100 entries, each ≤ 253 characters.
