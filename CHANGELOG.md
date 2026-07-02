# Changelog

Notable changes to `3brs/enterprise-security-bundle`. Follows
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [Unreleased]


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

[Unreleased]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3BRS/enterprise-security-bundle/releases/tag/v1.0.0