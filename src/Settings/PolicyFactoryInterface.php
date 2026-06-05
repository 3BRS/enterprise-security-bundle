<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings;

use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockoutPolicyInterface;
use ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\PasswordPolicyInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorMode;

interface PolicyFactoryInterface
{
    public function passwordPolicy(SettingsScope $scope): PasswordPolicyInterface;

    public function lockoutPolicy(SettingsScope $scope): LockoutPolicyInterface;

    public function twoFactorMode(SettingsScope $scope): TwoFactorMode;
}
