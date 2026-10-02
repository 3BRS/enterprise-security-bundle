# Changelog

Notable changes to `3brs/enterprise-security-bundle`. Follows
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [2.4.0] - 2026-10-02

### Security
- **Linking an OAuth account needs a full sign-in.** `AbstractOAuthCallbackController::handleLinkIntent()`
  took the current user from `Security::getUser()`, which also returns the user of scheb's
  `TwoFactorToken` — after the password, before the code — and `AbstractOAuthInitiateController`
  started `intent=link` without looking at the sign-in at all. With the OAuth routes on
  `PUBLIC_ACCESS`, which scheb lets through while a sign-in waits for its code, anyone who knew only
  the password could link their own provider account to the victim's and sign in through it from then
  on, without the code. For a `form_post` provider (Apple) the initiate step also put the victim into
  the signed state cookie, and the callback signed the attacker in on the spot.

  Both steps now link only after a full sign-in — what `IS_AUTHENTICATED_FULLY` grants with Symfony's
  and scheb's trust resolvers — checked by the new `FullSignInGuardTrait` through `isLinkAllowed()` on
  each controller. The initiate step throws `AccessDeniedException`, which the firewall answers with the
  code page or the sign-in page; the user's identifier goes into the state cookie only after a full
  sign-in; the callback with a session takes the current user only after a full sign-in. A sign-in
  restored from a remember-me cookie no longer links either, since a link adds a way into the account.
  Without the optional `Security` constructor argument, `AbstractOAuthInitiateController` refuses
  every link. Signing in through a provider while a sign-in waits for its code is unchanged — see
  [UPGRADE.md](UPGRADE.md#230--240).
- **Registering a passkey needs a full sign-in.** `AbstractPasskeyRegistrationOptionsController` and
  `AbstractPasskeyRegistrationVerifyController` took the user from any token, a remember-me one
  included, and a passkey signs in without the second factor: whoever held a stolen remember-me cookie
  could add their own passkey and keep a way into the account that needs neither the password nor the
  code. Where the registration routes were `PUBLIC_ACCESS`, a sign-in waiting for its code could do the
  same on the password alone. Both endpoints now answer `403` unless the sign-in is full, through
  `FullSignInGuardTrait` and the new `isRegistrationAllowed()` hook.
- **Managing the second factor needs a full sign-in.** `AbstractTwoFactorSetupController`,
  `AbstractTwoFactorDisableController` and `AbstractTwoFactorRegenerateRecoveryCodesController` took
  the user from any token too. A stolen remember-me cookie was enough to switch 2FA off, enrol a
  second factor of the attacker's own (locking the owner out of the password sign-in), or take a fresh
  set of recovery codes, which then pass the second factor together with the password. Where those
  routes allowed `IS_AUTHENTICATED` (which scheb's token satisfies), a sign-in waiting for its code
  could do the same on the password alone. All three now redirect a sign-in that is not full to
  `getLoginUrl()`.
- **Switching two-factor authentication off and regenerating recovery codes can ask for a code.**
  `AbstractTwoFactorDisableController` checked the CSRF token only, so anyone with the signed-in
  session disabled 2FA in one click; `AbstractTwoFactorRegenerateRecoveryCodesController` handed the
  same session a fresh set of recovery codes, one of which would confirm the disable just as well.
  Given scheb's TOTP authenticator as the new optional `$totpAuthenticator` constructor argument,
  both take the current TOTP code (`TotpAuthenticator::checkCode()`) or a recovery code (the
  `verifyRecoveryCode()` hook) from `_code`. With the also new optional `$rateLimitGuard` they count
  every submitted code against the user under one `two_factor_code` action, group from
  `getRateLimitGroup()`, leave an empty field uncounted and clear the counter once the action is done.
  A refused code flashes `three_brs.two_factor.confirmation_code_invalid` and goes to
  `getRedirectAfterRefusedCodeUrl()`. No password is asked: accounts created through a social sign-in
  have none. Both arguments are optional so that subclasses keep working; without `$totpAuthenticator`
  the controllers act on the CSRF token alone, as before. `$totpAuthenticator` without
  `$rateLimitGuard` throws a `LogicException` in the constructor, since the code could then be guessed
  without limit. The limit is on by default: while the settings store has no
  `rate_limit.two_factor_code.*`, `DynamicRateLimiterFactory` counts 5 attempts per 15 minutes rather
  than reading the missing `enabled` as off.

### Added
- **`TwoFactorCodeConfirmationTrait`** — the code check shared by the disable and regenerate
  controllers: `confirmCode()`, `clearCodeAttempts()`, `isValidCode()`, `verifyRecoveryCode()`,
  `getRateLimitGroup()` and `getRedirectAfterRefusedCodeUrl()`.
- **`FullSignInGuardTrait`** — `isFullSignIn(?TokenInterface $token)`, the check shared by the OAuth
  link, the passkey registration and the two-factor setup, disable and regenerate controllers: a token
  with a user that is neither scheb's `TwoFactorTokenInterface` nor a `RememberMeToken`, i.e. what
  `IS_AUTHENTICATED_FULLY` grants with Symfony's and scheb's trust resolvers.
- **`DynamicRateLimiterFactory::__construct()` takes `$actionDefaults`** — per action, the `enabled`,
  `limit` and `interval` used while the settings store has no `rate_limit.{action}.*`. A value the
  store holds, `false` included, wins. The bundle's service registers `two_factor_code` there; a
  settings layer that defines the key should default `enabled` to `true`.
- **`PendingSignInCanceller` and `CancelPendingSignInRequiredHandler`** end a sign-in that waits for
  its two-factor code when the user opens another page of the firewall after the code page was shown.
  Scheb keeps such a sign-in until the session expires and sends every page that is not public — on
  a typical shop the home page and the catalogue, which carry no `access_control` rule — back to the
  code page, so a user who clicked the logo kept landing on it. The handler decorates scheb's
  `security.authentication.authentication_required_handler.two_factor.<firewall>` and opens the
  requested page again without the sign-in; the canceller covers `PUBLIC_ACCESS` pages on
  `kernel.request` right after the firewall. Only page loads cancel, never background requests from
  the code page, and only once scheb's `FORM` event marked the code page as shown — the sign-in page
  excepted, which cancels at once. The two-factor pages never cancel. Opt-in per firewall, since it
  changes scheb's behaviour — and it reads the session on `PUBLIC_ACCESS` page loads from visitors
  with a session cookie, which makes those responses `private`.

### Fixed
- **`TwoFactorAwareAuthenticationSuccessHandler` passes the firewall's options on.** Symfony calls
  `setOptions()` and `setFirewallName()` only on the handler named in the firewall's
  `success_handler`, and the wrapper had neither, so the wrapped handler never learnt
  `default_target_path`, `use_referer` or the firewall name — a user without a 2FA challenge landed
  on `/` instead of on `default_target_path` or on the protected page that sent them to sign in. The
  wrapper now implements both and hands them to the wrapped handler when it has them, as Symfony's
  `CustomAuthenticationSuccessHandler` does. The wrapped handler is a shared service, so they go to a
  copy of it; another firewall wrapping the same service keeps its own.
- The configuration guide no longer says the rate-limiter cache pool needs no action. The bundle
  builds `three_brs.rate_limiter.cache_pool` on `cache.app`, which is a filesystem cache unless
  configured otherwise; with more than one instance of the application the pool has to be shared
  (Redis, Memcached, …), or every instance counts its own limits.
- The two-factor guide no longer wires `security.authentication.success_handler.<firewall>.form_login`
  as the wrapped handler: with `success_handler` set, that is the service Symfony builds around the
  wrapper itself.

## [2.3.0] - 2026-08-24

### Added
- **`AbstractPasskeyAssertionVerifier`** — the verify half of a WebAuthn assertion, which every
  consumer wrote out by hand (the guide even shipped the ~40-line skeleton to copy). The abstract
  runs the ceremony; the subclass supplies the options session key, the credential's owner, its
  result DTO and the flush. The `commit()` hook exists so the sign-count write stays inside the
  verifier: it has to be atomic with the check, or two concurrent assertions replaying the same
  authenticator response both pass before either one's counter lands. That invariant now lives in
  one place instead of in each copy.
- **`AbstractNewDeviceDetector`** and **`KnownDeviceRecordInterface`** — the check-and-remember step
  behind login notifications, together in one call because the two halves must not be separable: two
  concurrent sign-ins from the same device would both read "unknown" and both email the user. The
  insert race is settled by the unique key on the consumer's `(user, fingerprint)` columns, with the
  subclass naming the exception that means conflict — the same shape `AbstractSessionTracker`
  already uses, so no Doctrine dependency enters the bundle.

## [2.2.2] - 2026-08-24

### Added
- **English translation catalogues** in `src/Resources/translations/` — `validators.en.yaml`,
  `flashes.en.yaml`, `messages.en.yaml` — covering every message id the bundle emits. Symfony
  registers a bundle's translation directory itself, so an id the consumer had not defined stops
  surfacing to end users as the raw `three_brs.*` string. They are defaults, not fixtures: the app's
  `translations/` directory and any bundle registered later both override them, and English is all
  that ships — other locales stay the consumer's. A unit test holds the catalogues and the ids in
  `src/` to each other in both directions, so neither a new id without wording nor wording for an id
  that no longer exists gets through.
- **`AbstractTwoFactorSetupController::getIssuer()`**, alongside the `isRecoveryCodesEnabled()` /
  `getRecoveryCodesCount()` hooks that were already there, and the provisioning URI is now built
  from it. A consumer resolving the TOTP issuer at runtime (per tenant, per brand, from DB-backed
  settings) overrides one method instead of copying ~60 lines of `__invoke()`.

### Fixed
- **An unknown `two_factor_authentication.mode` no longer takes the whole application down.**
  `PolicyFactory::twoFactorMode()` called `TwoFactorMode::from()` on a value read from a settings
  store the bundle does not own, so anything outside `disabled` / `allowed` / `enforced` — a direct
  SQL write, a data migration, a restore from an older database, a consumer filling settings from
  its own code — threw a `\ValueError`. The mode is read on every request of a signed-in user,
  including the settings page where the value could have been corrected, so one bad row meant an
  HTTP 500 with no way out through the UI. It now falls back to `DISABLED`: an unrecognised value
  must neither switch a second factor on by itself nor quietly stop enforcing one.

### Changed
- **A failed OAuth provider call flashes `three_brs.ui.social_login.provider_error`** instead of the
  exception's message. Every other flash in `AbstractOAuthCallbackController` is a translation key;
  this one handed the user developer-facing English that, for a failed profile fetch, could include
  the provider's raw response body. The message now goes to the logger at `warning` under
  `{audit channel}.provider_error` with the exception attached, so nothing is lost for diagnosis.
  Consumers that render OAuth flashes untranslated need the new key — see
  [UPGRADE.md](UPGRADE.md#22--222).

## [2.2.1] - 2026-08-20

### Fixed
- **Corrected a claim introduced in 2.2.0.** The admin guide's "block account" action said the block
  "covers both the next sign-in and the ones already open". Only the first half is true on its own:
  `enabled = false` stops the next sign-in, while revoking stamps `revokedAt` and closes nothing
  until the [session revocation listener](docs/controllers-you-provide.md#8-session-revocation-listener)
  is in place. The clause was added while rewriting 2.2.0's corrections from audit notes into
  instructions, and reintroduced exactly the defect that release set out to remove — a summary
  asserting an outcome the code delivers only with the integrator's help.

## [2.2.0] - 2026-08-20

### Added
- **`RateLimitGuard` can pair a username-keyed action with a per-address companion counter**, via the
  new `$ipCompanionActions` map (e.g. `['login' => 'login_ip']`). This closes password spraying,
  which the username-keyed `login` limit and the lockout counter both miss by construction: an
  attacker spreading a few common passwords over many accounts stays under every per-account
  threshold. Both counters are consumed before either verdict is acted on, so a tripped username
  cannot shield the address counter; the companion is skipped when no username was passed, since the
  primary counter is keyed on the address already. The map is **empty by default** — behaviour and
  settings reads are unchanged until a consumer fills it in, and the companion carries its own
  `rate_limit.{action}.*` settings so an address limit is not forced to reuse a per-account number.

### Fixed
- **Declared `symfony/clock`.** `services.yaml` binds the `clock` service in three places but the
  package was never required — it only resolved because `symfony/security-bundle` happens to pull it
  in. Now explicit, so a change upstream cannot break container compilation here.
- PHPUnit now reports the detail of deprecations it triggers, instead of only their count.

### Security
- **The signed OAuth state cookie now carries its own expiry.** `StateCookieSigner` stamps an `exp`
  into the signed body and refuses anything past it, or carrying none. Previously the only bound on
  the value's lifetime was the cookie's `Expires` attribute — a hint to a cooperating browser, which
  an attacker replaying a captured value simply ignores. Because a `link` cookie names the user the
  callback signs in, any copy that outlived the browser's window (an exported HAR, a proxy or WAF
  log, a captured request in an error report) stayed a working sign-in for that account forever,
  unaffected by logout, a password change or "revoke all sessions".

  Exploiting this needed the value in the first place, and whoever can read a victim's cookie jar
  can usually read their session cookie too — so this is hardening, not a break anyone was standing
  on. It applies only to providers marked `FormPostOAuthProviderInterface` (of the bundled ones,
  Apple) and only to `intent=link`, since `login` carries no user.

### Changed
- `StateCookieSigner::__construct()` takes `ClockInterface $clock` and `int $ttl = 600` after
  `$secret`. `StateCookieSignerInterface` is unchanged, so consumers that only call `encode()` /
  `decode()` need no edit — see [UPGRADE.md](UPGRADE.md#21--22) if you register the service yourself.
  State cookies issued before the upgrade are refused, costing anyone mid-sign-in one retry.

- **Documented how rate-limit counters are keyed**, and that `RateLimitGuard::buildKey()` is the
  intended override point. The account-lockout guide now states the `trusted_proxies` prerequisite
  as a precondition for enabling any IP-keyed action rather than a closing footnote — unconfigured,
  every visitor reads as one address and the limiter shuts the endpoint for all of them; configured
  too widely, `X-Forwarded-For` becomes attacker-supplied. It also warns against substituting a CDN
  header for `getClientIp()`, and no longer claims the `login` limit slows credential stuffing:
  keyed on the username it bounds guesses per account, exactly as the lockout counter does, and
  spraying is built to stay under both.

- **Swept the remaining documentation for the same defect** — a claim of protection the code does not
  implement — and corrected ten of them. The bundle is contract-first, so the recurring shape was a
  feature summary written in bundle voice for something that is actually an abstract hook or an
  uncalled service. Fixed: 2FA `enforced` mode (`shouldEnforceFor*()` has no caller in `src/`;
  nothing holds an un-enrolled user at setup, and wiring the success handler does not change that),
  magic-link timing padding (`padTo()` has no caller; the neutral response *body* is bundle
  behaviour, the neutral response *time* is not), the admin "block account" / "sign out from all
  devices" actions (revoking is a `revokedAt` stamp, not a sign-out), the passkey and OAuth
  last-method guards (`canRemoveCredential()` / `canUnlinkProvider()` are abstract — the definition
  of "last method" is the integrator's), the WebAuthn ceremony (`verifyAndPersist()` is abstract),
  `password_expiration` (documented as readable in the `global` scope, which the checker never
  consults), the account-state message key (three of five controllers flash it; the passkey endpoint
  answers `403` and the recovery challenge throws), and the passkey verify request shape
  (`{"credential": "<string>"}`, not the credential JSON raw).

Documentation-only corrections, of statements that promised a guarantee the code does not give:

- **`AutoRegistrationPolicy` no longer documented as requiring a verified email.** It refuses only on
  `isEmailVerified() === false` and accepts `null`; only `GoogleOAuthProvider` sets the flag. Added
  what each provider actually attests: Google and Apple do, Entra emits no `email_verified` and warns
  against using `email` for authorization — its `xms_edov` claim covers this but is off by default.
- **"Enforces revocation" reworded** in the session-management guide. The bundle only stamps
  `revokedAt`; the sign-out listener is the integrator's. Correct further down the page, misleading
  in the feature summary.
- **`findExistingLinkUser()` contract stated**: resolve by `(provider, providerUserId)`, never by
  email — that branch signs the user in with no ownership proof.
- **Warned against Microsoft `tenant: 'common'` with auto-registration**, in the Entra setup section
  and inline in the `configuration.md` example.

## [2.1.0] - 2026-07-14

### Added
- `AccountStateGuardTrait` — holds the `UserCheckerInterface` and the `isAccountAllowedToSignIn()`
  predicate that the sign-in controllers guard themselves with, plus the `ACCOUNT_REFUSED_MESSAGE`
  key they flash when they turn a refused account away.
- `AbstractAccountDeletionRequestController::isDeletionConfirmed(FormInterface $form, UserInterface $user): bool`
  — the re-authentication before a deletion request is now an overridable hook. The default is the
  previous behaviour (the current password); a subclass whose accounts have no password (created by
  a social sign-up, for instance) overrides it with the confirmation it does have. It returns `false`
  instead of throwing when the form carries no password field, and the failure message moved to the
  overridable `NOT_CONFIRMED_MESSAGE` constant (was the hard-coded
  `three_brs.account_deletion.invalid_password`).

### Changed
- The controllers that sign a user in outside the firewall now enforce the account state.
  `AbstractMagicLinkVerifyController`, `AbstractPasskeyLoginVerifyController`,
  `AbstractOAuthCallbackController`, `AbstractOAuthConfirmLinkController` and
  `AbstractTwoFactorRecoveryChallengeController` each run `UserCheckerInterface::checkPreAuth()`
  before writing the security token. They write it directly (so the second factor, which guards
  password sign-in, is not challenged), which means the firewall's user checker never ran for them:
  an account disabled by an administrator — or one with a self-service deletion pending — could sign
  straight back in through a magic link, a social account, a passkey or a recovery code.
- The refusal happens before anything is mutated: the magic link is not consumed (it still works once
  the account is enabled again), the social-account link is not created, the recovery code is not
  spent. Each controller answers it itself — a flash (`three_brs.account_state.sign_in_refused`) plus
  a redirect, a `403` from the passkey verify endpoint (it answers a `fetch()`), or an
  `AccessDeniedException` from the two-factor recovery challenge — so no `AccountStatusException`
  escapes into the firewall.
- Each of those five controllers gained a **last constructor argument**
  `Symfony\Component\Security\Core\User\UserCheckerInterface $userChecker`. Bind a checker that
  refuses on the account state alone, not the firewall's checker chain (see UPGRADE.md).
- `PasswordPolicyFilteringValidator` no longer carries the message key of any particular framework.
  The host application names its own redundant password-length messages in the new parameter
  `three_brs.password_policy.redundant_message_templates` (constructor argument
  `$redundantMessageTemplates`, empty by default); Symfony's `Length` constraint is still recognised
  without configuration.

## [2.0.0] - 2026-07-02

### Added
- `OAuthLinkCodeGenerator` (`OAuthLinkCodeGeneratorInterface`) — optional confirm-link helper
  that mints a zero-padded 6-digit one-time code and SHA-256-hashes it for storage/comparison.
- `CodeChallengeValidator` (`CodeChallengeValidatorInterface`) — optional confirm-link helper for
  the **verify** half of a one-time-code challenge: enforces expiry + attempt limit + single-use +
  constant-time compare over a transport-agnostic `CodeChallengeState`, returning a
  `CodeChallengeOutcome` (verdict + next state to persist). Clock-driven; never touches the session.
- Cross-site `form_post` OAuth provider support (e.g. Apple Sign In): the
  `FormPostOAuthProviderInterface` opt-in marker plus a dedicated `SameSite=None; Secure;
  HttpOnly` single-use **HMAC-signed** state cookie carrying state / intent / link-initiating
  user across the cross-site POST (the session cookie is not sent there). GET-redirect
  providers (Google, Microsoft) are unaffected.
- `StateCookieSigner` (`StateCookieSignerInterface`) — signs and verifies that state cookie so
  its payload (including the link-initiating user) cannot be forged or tampered with by the client.

### Changed
- Password-login control is now a single **scope-wide** toggle instead of a per-user
  preference. `AbstractPasswordLoginCheckListener` no longer takes a preference repository
  in its constructor and no longer performs a per-user lookup; it blocks every password
  login for the bound user type when the scope toggle is off. Its abstract hook
  `isFeatureEnabled()` is replaced by `isPasswordLoginEnabled()` (return `true` when
  password login is allowed for the scope).
- Renamed settings key `password_login_control` → `password_login`.
- `AbstractOAuthConfirmLinkController` no longer performs a hard-coded password check on
  confirm-link. Account ownership is now proven via two new abstract hooks subclasses **must**
  implement: `prepareChallenge(UserInterface $user, array $pending, Request $request): void`
  (issues the ownership-proof challenge on the initial GET; should be idempotent across
  refreshes) and `verifyChallenge(UserInterface $user, array $pending, Request $request): ?string`
  (verifies the submitted proof on POST; returns `null` on success or a translation key on
  failure). `__invoke()` keeps its signature but delegates the check to these hooks instead of
  reading the `_password` request field.
- `AbstractOAuthInitiateController` gained a `StateCookieSignerInterface` constructor argument
  (and an optional `Security` to capture the logged-in user for a link); `AbstractOAuthCallbackController`
  gained a `StateCookieSignerInterface` argument and a new abstract hook
  `findUserByIdentifier(string $identifier): ?UserInterface` that resolves the link-initiating
  user from the verified state cookie on a cross-site callback.

### Removed
- `PasswordLoginPreferenceInterface` and `PasswordLoginPreferenceRepositoryInterface` — the
  per-user password-login preference contracts (the listener now reads a scope toggle, not a
  per-user record).
- Constructor argument `UserPasswordHasherInterface $passwordHasher` (and the promoted
  property) from `AbstractOAuthConfirmLinkController` — the base class no longer verifies
  passwords; its constructor is now `($tokenStorage, $router, $twig, $logger)`.
- The fixed error key `three_brs.ui.social_login.invalid_password` from
  `AbstractOAuthConfirmLinkController` — failure keys now come from the subclass's
  `verifyChallenge()`.

## [1.1.0] - 2026-06-17

### Added
- `getCreatedAt(): ?\DateTimeInterface` on `PasswordExpiration{Shop,Admin}UserInterface`.

### Changed
- `PasswordExpirationChecker` no longer treats a missing `passwordChangedAt` as
  expired — it falls back to `getCreatedAt()`. Enabling expiration no longer
  forces a password reset on every existing user.
- Magic-link and passkey login now bypass 2FA (authenticate directly, like
  OAuth). 2FA guards plain password login only.
- Constructors of `AbstractMagicLinkVerifyController` and
  `AbstractPasskeyLoginVerifyController` lost their 2FA arguments.

### Removed
- Parameter `three_brs.passkey.skip_2fa_when_user_verified` (and its setting key).
- `PasskeyAssertionResultInterface::isUserVerified()`.

### Fixed
- Stray character at the end of `README.md`.

## [1.0.0] - 2026-06-15
- Initial release.

[2.4.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v2.3.0...v2.4.0
[2.1.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3BRS/enterprise-security-bundle/releases/tag/v1.0.0