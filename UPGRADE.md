bud# Upgrade

## 1.0 → 1.1

1. **Add `getCreatedAt()` to your password-expiration user entities.**
   `PasswordExpiration{Shop,Admin}UserInterface` now require
   `public function getCreatedAt(): ?\DateTimeInterface;` — used as the
   expiration fallback. Most entities already expose a `createdAt`.

2. **Magic-link and passkey now bypass 2FA.** They authenticate directly; 2FA
   guards plain password login only. Review against your security policy.

3. **Update verify-controller constructors** — drop the removed arguments from
   your subclasses and service definitions:
   - `AbstractMagicLinkVerifyController`: removed `$eventDispatcher`, `$twoFactorHandler`.
   - `AbstractPasskeyLoginVerifyController`: removed `$eventDispatcher`, `$twoFactorHandler`, `$skipTwoFactorWhenUserVerified`.

4. **Remove the parameter** `three_brs.passkey.skip_2fa_when_user_verified`.

5. **`PasskeyAssertionResultInterface::isUserVerified()` is gone** — only
   `getUser()` is required now.

## 1.1 → X.Y


1. **Password-login control is now scope-wide, not per-user.** If you extended
   `AbstractPasswordLoginCheckListener`:
   - Rename your `isFeatureEnabled()` override to `isPasswordLoginEnabled()` and invert its
     meaning: return `true` when password login is **allowed** for the scope. (Previously the
     base gated on `isFeatureEnabled()` and then a per-user `isPasswordLoginAllowedForUser()`
     lookup; now the single hook decides.)
   - Drop the `PasswordLoginPreferenceRepositoryInterface` constructor argument from your
     subclass and its service definition — the base constructor is gone.
   - `PasswordLoginPreferenceInterface` and `PasswordLoginPreferenceRepositoryInterface` are
     removed; delete your implementations (and the per-user preference storage if it served
     no other purpose).
   - Rename the settings key `password_login_control` → `password_login` wherever you set
     defaults or read the toggle (e.g. `password_login.enabled`).

2. **OAuth confirm-link is now challenge-based, not password-based.** If you extended
   `AbstractOAuthConfirmLinkController`:
   - The matched account no longer needs to be a `PasswordAuthenticatedUserInterface` —
     passwordless accounts can complete confirm-link once you implement a challenge.
   - Drop the `UserPasswordHasherInterface $passwordHasher` argument from your subclass
     constructor and its service definition — the base constructor is now
     `($tokenStorage, $router, $twig, $logger)`; remove any `$this->passwordHasher` usage.
   - Implement `prepareChallenge(UserInterface $user, array $pending, Request $request): void`
     — issue the ownership proof on the initial GET (e.g. generate a one-time code, email it,
     persist its hash + expiry). Make it idempotent so a refresh does not re-send.
   - Implement `verifyChallenge(UserInterface $user, array $pending, Request $request): ?string`
     — validate the submitted proof on POST (read your own field, e.g. `_code`, instead of the
     old `_password`); return `null` on success or a translation key on failure.
   - Update your confirm-link template/form: stop submitting `_password`, submit whatever
     `verifyChallenge()` reads, and define/translate your own failure key — the base no longer
     emits `three_brs.ui.social_login.invalid_password`.
   - (Optional) `OAuthLinkCodeGenerator` is a ready-made helper for a code-based challenge:
     `generateCode()` mints the 6-digit code, `hash()` (SHA-256) stores/compares it. Reference
     it by its concrete service id — there is no interface alias for autowiring.
