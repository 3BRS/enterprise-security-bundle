<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration;

interface PasswordExpirationShopUserInterface
{
    public function getPasswordChangedAt(): ?\DateTimeImmutable;

    public function setPasswordChangedAt(?\DateTimeImmutable $passwordChangedAt): void;

    public function isForcePasswordChange(): bool;

    public function setForcePasswordChange(bool $forcePasswordChange): void;

    /**
     * Account creation timestamp. Used as the password-expiration reference
     * fallback for users with no recorded password change yet (e.g. accounts
     * created before this feature was in place), so enabling expiration does not
     * force an immediate change on everyone.
     */
    public function getCreatedAt(): ?\DateTimeInterface;
}
