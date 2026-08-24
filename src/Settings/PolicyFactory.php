<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings;

use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockoutPolicy;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockoutPolicyInterface;
use ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\PasswordPolicy;
use ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\PasswordPolicyInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorMode;

class PolicyFactory implements PolicyFactoryInterface
{
    public function __construct(
        protected SettingsProviderInterface $provider,
    ) {
    }

    public function passwordPolicy(SettingsScope $scope): PasswordPolicyInterface
    {
        return new PasswordPolicy(
            $this->provider->getInt('password_policy.min_length', $scope),
            $this->provider->getNullableInt('password_policy.max_length', $scope),
            $this->provider->getBool('password_policy.require_uppercase', $scope),
            $this->provider->getBool('password_policy.require_lowercase', $scope),
            $this->provider->getBool('password_policy.require_numbers', $scope),
            $this->provider->getBool('password_policy.require_special_characters', $scope),
        );
    }

    public function lockoutPolicy(SettingsScope $scope): LockoutPolicyInterface
    {
        return new LockoutPolicy(
            $this->provider->getBool('account_lockout.enabled', $scope),
            $this->provider->getInt('account_lockout.max_attempts', $scope),
            $this->provider->getNullableInt('account_lockout.auto_unlock_after', $scope),
        );
    }

    public function twoFactorMode(SettingsScope $scope): TwoFactorMode
    {
        // The value comes from a settings store the bundle does not own (a DB row, a YAML file,
        // whatever the consumer wired up), so it can hold anything a direct write put there.
        // `from()` would throw on an unknown value, and the mode is read on every request of a
        // signed-in user — including the settings page where the value could be corrected — so one
        // bad row would mean an HTTP 500 nobody can clear through the UI. DISABLED is the fallback
        // because an unrecognised value must not silently turn a second factor on, nor silently
        // stop enforcing one that was set to `enforced`: it fails to a state the consumer can see.
        return TwoFactorMode::tryFrom($this->provider->getString('two_factor_authentication.mode', $scope))
            ?? TwoFactorMode::DISABLED;
    }
}
