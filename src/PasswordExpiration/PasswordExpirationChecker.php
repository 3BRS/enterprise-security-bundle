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
        return $this->isExpired($user->isForcePasswordChange(), $user->getPasswordChangedAt(), $user->getCreatedAt(), SettingsScope::CUSTOMER);
    }

    public function isAdminUserPasswordExpired(PasswordExpirationAdminUserInterface $user): bool
    {
        return $this->isExpired($user->isForcePasswordChange(), $user->getPasswordChangedAt(), $user->getCreatedAt(), SettingsScope::ADMIN);
    }

    protected function isExpired(
        bool $forcePasswordChange,
        ?\DateTimeImmutable $changedAt,
        ?\DateTimeInterface $createdAt,
        SettingsScope $scope,
    ): bool {
        if ($forcePasswordChange) {
            return true;
        }

        if (! $this->settings->getBool('password_expiration.enabled', $scope)) {
            return false;
        }

        // Users with no recorded password-change date (e.g. accounts created
        // before this feature was in place) fall back to the account creation
        // date, so enabling expiration does not force an immediate change on every
        // existing user — only those whose account is already older than the
        // window. Once the user changes their password, passwordChangedAt is
        // stamped and takes over.
        $referenceDate = $changedAt ?? ($createdAt !== null ? \DateTimeImmutable::createFromInterface($createdAt) : null);

        if ($referenceDate === null) {
            return false;
        }

        $days = $this->settings->getInt('password_expiration.days', $scope);
        $expiresAt = $referenceDate->modify(sprintf('+%d days', $days));

        return new \DateTimeImmutable() > $expiresAt;
    }
}
