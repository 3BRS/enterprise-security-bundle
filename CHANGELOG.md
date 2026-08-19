# Changelog

Notable changes to `3brs/enterprise-security-bundle`. Follows
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [Unreleased]

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

[2.1.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3BRS/enterprise-security-bundle/releases/tag/v1.0.0