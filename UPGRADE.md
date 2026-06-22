# Upgrade

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

6. **OAuth confirm-link is now challenge-based, not password-based.**
   `AbstractOAuthConfirmLinkController` dropped `$passwordHasher` from its constructor and
   added two abstract methods to implement: `prepareChallenge(UserInterface $user, array
   $pending, Request $request): void` (issue the ownership proof, e.g. email a code) and
   `verifyChallenge(UserInterface $user, array $pending, Request $request): ?string`
   (return `null` on success, otherwise a translation key). Update your subclasses and
   their service definitions accordingly.
