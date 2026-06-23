# Changelog

Notable changes to `3brs/enterprise-security-bundle`. Follows
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [Unreleased]

_Targets 1.1.0. Integrators must apply the steps in [UPGRADE.md](UPGRADE.md)._

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

[Unreleased]: https://github.com/3BRS/enterprise-security-bundle/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/3BRS/enterprise-security-bundle/releases/tag/v1.0.0
