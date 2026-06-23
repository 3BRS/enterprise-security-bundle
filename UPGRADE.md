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
