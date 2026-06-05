<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Lockout;

/**
 * Generic lockout-state contract. Added to your `User` entity (or extended via
 * the firewall-specific `LockableAdminUserInterface` / `LockableShopUserInterface`
 * aliases for apps using the Sylius two-firewall layout).
 */
interface LockableUserInterface
{
    public function getFailedLoginAttempts(): int;

    public function setFailedLoginAttempts(int $failedLoginAttempts): void;

    public function getLastFailedLoginAt(): ?\DateTimeImmutable;

    public function setLastFailedLoginAt(?\DateTimeImmutable $lastFailedLoginAt): void;

    public function getLockedAt(): ?\DateTimeImmutable;

    public function setLockedAt(?\DateTimeImmutable $lockedAt): void;

    public function getLockoutUntil(): ?\DateTimeImmutable;

    public function setLockoutUntil(?\DateTimeImmutable $lockoutUntil): void;
}
