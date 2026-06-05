<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings;

use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorMode;

class FeatureToggle implements FeatureToggleInterface
{
    public function __construct(
        protected SettingsProviderInterface $provider,
    ) {
    }

    public function isEnabled(string $feature, SettingsScope $scope): bool
    {
        return $this->provider->getBool($feature . '.enabled', $scope);
    }

    public function isTwoFactorActive(SettingsScope $scope): bool
    {
        // 2FA has no `enabled` flag — it is gated by a three-state mode
        // (disabled / allowed / enforced); the menu / setup pages only make
        // sense when the mode is non-disabled.
        return $this->provider->getString('two_factor_authentication.mode', $scope) !== TwoFactorMode::DISABLED->value;
    }
}
