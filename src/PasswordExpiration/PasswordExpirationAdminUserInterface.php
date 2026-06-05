<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration;

interface PasswordExpirationAdminUserInterface
{
    public function getPasswordChangedAt(): ?\DateTimeImmutable;

    public function setPasswordChangedAt(?\DateTimeImmutable $passwordChangedAt): void;

    public function isForcePasswordChange(): bool;

    public function setForcePasswordChange(bool $forcePasswordChange): void;
}
