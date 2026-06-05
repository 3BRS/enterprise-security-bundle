<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration;

interface PasswordExpirationCheckerInterface
{
    public function isShopUserPasswordExpired(PasswordExpirationShopUserInterface $user): bool;

    public function isAdminUserPasswordExpired(PasswordExpirationAdminUserInterface $user): bool;
}
