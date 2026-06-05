<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use ThreeBRS\EnterpriseSecurityBundle\Settings\PolicyFactoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class TwoFactorEnforcementChecker implements TwoFactorEnforcementCheckerInterface
{
    public function __construct(
        protected PolicyFactoryInterface $policyFactory,
    ) {
    }

    public function shouldEnforceForShopUser(TwoFactorAuthShopUserInterface $user): bool
    {
        return $this->policyFactory->twoFactorMode(SettingsScope::CUSTOMER)->isEnforced() && ! $user->isTwoFactorEnabled();
    }

    public function shouldEnforceForAdminUser(TwoFactorAuthAdminUserInterface $user): bool
    {
        return $this->policyFactory->twoFactorMode(SettingsScope::ADMIN)->isEnforced() && ! $user->isTwoFactorEnabled();
    }
}
