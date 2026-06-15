# Entities & persistence

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle is ORM-agnostic: it ships **contracts**, and your app owns the Doctrine entities, mappings and migrations. This page covers the two halves of that — the mixin interfaces your `User` entity implements, and the standalone records you persist.

## User entity setup

Your user entity must implement the appropriate bundle contract interfaces depending on which features you enable.

```php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockableShopUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration\PasswordExpirationShopUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorAuthShopUserInterface;

#[ORM\Entity]
class User implements
    UserInterface,
    PasswordAuthenticatedUserInterface,
    TwoFactorAuthShopUserInterface,
    LockableShopUserInterface,
    PasswordExpirationShopUserInterface
{
    // ... your standard user fields (id, email, password, roles)

    // Two-factor (from TwoFactorAuthShopUserInterface)
    #[ORM\Column(nullable: true)]
    protected ?string $totpSecret = null;

    #[ORM\Column(type: 'boolean')]
    protected bool $twoFactorEnabled = false;

    #[ORM\Column(type: 'integer')]
    protected int $trustedTokenVersion = 0;

    public function getTotpSecret(): ?string { return $this->totpSecret; }
    public function setTotpSecret(?string $s): void { $this->totpSecret = $s; }
    public function isTwoFactorEnabled(): bool { return $this->twoFactorEnabled; }
    public function setTwoFactorEnabled(bool $v): void { $this->twoFactorEnabled = $v; }
    public function getTrustedTokenVersion(): int { return $this->trustedTokenVersion; }
    public function bumpTrustedTokenVersion(): void { ++$this->trustedTokenVersion; }

    // Lockout (from LockableShopUserInterface)
    #[ORM\Column(type: 'integer')]
    protected int $failedLoginAttempts = 0;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    protected ?\DateTimeImmutable $lockedUntil = null;

    // … getters/setters per the interface
}
```

The available user-mixin contracts (add per feature you enable):

| Interface (shop / admin flavor) | Feature |
|---|---|
| `TwoFactorAuthShopUserInterface` / `TwoFactorAuthAdminUserInterface` | Two-factor authentication |
| `LockableShopUserInterface` / `LockableAdminUserInterface` | Account lockout |
| `PasswordExpirationShopUserInterface` / `PasswordExpirationAdminUserInterface` | Password expiration |

> **About the `Shop` / `Admin` naming:** the two flavors are identical contracts — historic naming from Sylius (which has two firewalls: shop = customers, admin = staff). If your app has **one** firewall, pick either flavor and stick with it. If you have **two** firewalls and want them feature-flagged independently, use both. Bundle abstract controllers work with any firewall via `getFirewallName()`.

The mixin methods are thin (plain getters/setters over a few columns) — implement them directly on your entity, or fold them into a trait you reuse across firewalls.

## Persisted entities you must provide

The bundle defines **record contracts** for some entities; for others it just consumes data your repository returns. Either way, you persist these in your ORM and create migrations for them.

| Entity | Bundle contract | Fields (typical) |
|---|---|---|
| `UserMagicLinkToken` | implements `MagicLinkRecordInterface` | id, user FK, tokenHash, expiresAt, usedAt, createdAt |
| `UserSession` | implements `SessionRecordInterface` | id, user FK, sessionId, userAgent, ipAddress, country, city, createdAt, lastActivityAt, revokedAt |
| `UserSocialAccountLink` | implements `SocialAccountLinkRecordInterface` | id, user FK, provider, providerUserId, email, linkedAt, lastUsedAt |
| `UserDeletionRequest` | implements `CustomerDeletionRequestRecordInterface` | id, user FK, requestedAt, scheduledFor, cancelledAt, requestedByAdmin |
| `UserPasskeyCredential` | implements `PasskeyCredentialRecordInterface` | id, user FK, credentialId, credentialSource (array), label, createdAt, lastUsedAt |
| `UserRecoveryCode` | *(your shape — hash via bundle's `RecoveryCodeGeneratorInterface`)* | id, user FK, codeHash, consumedAt |
| `UserPasswordHistory` | *(optional — only if you wire `PasswordHistory` constraint into your password-change form)* | id, user FK, passwordHash, createdAt |

Write thin Doctrine repositories with the lookup methods your controllers will need (`findActiveForUser`, `findOneByTokenHash`, etc.). Generate migrations the usual way (`bin/console doctrine:migrations:diff`).
