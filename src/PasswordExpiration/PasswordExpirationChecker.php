<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration;

use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class PasswordExpirationChecker implements PasswordExpirationCheckerInterface
{
    public function __construct(
        protected SettingsProviderInterface $settings,
    ) {
    }

    public function isShopUserPasswordExpired(PasswordExpirationShopUserInterface $user): bool
    {
        return $this->isExpired($user->isForcePasswordChange(), $user->getPasswordChangedAt(), SettingsScope::CUSTOMER);
    }

    public function isAdminUserPasswordExpired(PasswordExpirationAdminUserInterface $user): bool
    {
        return $this->isExpired($user->isForcePasswordChange(), $user->getPasswordChangedAt(), SettingsScope::ADMIN);
    }

    protected function isExpired(bool $forcePasswordChange, ?\DateTimeImmutable $changedAt, SettingsScope $scope): bool
    {
        if ($forcePasswordChange) {
            return true;
        }

        if (! $this->settings->getBool('password_expiration.enabled', $scope)) {
            return false;
        }

        if ($changedAt === null) {
            return true;
        }

        $days = $this->settings->getInt('password_expiration.days', $scope);
        $expiresAt = $changedAt->modify(sprintf('+%d days', $days));

        return new \DateTimeImmutable() > $expiresAt;
    }
}
