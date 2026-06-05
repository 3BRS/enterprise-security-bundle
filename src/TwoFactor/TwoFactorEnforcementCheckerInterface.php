<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

interface TwoFactorEnforcementCheckerInterface
{
    public function shouldEnforceForShopUser(TwoFactorAuthShopUserInterface $user): bool;

    public function shouldEnforceForAdminUser(TwoFactorAuthAdminUserInterface $user): bool;
}
