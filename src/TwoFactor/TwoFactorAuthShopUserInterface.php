<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface as TotpTwoFactorInterface;
use Scheb\TwoFactorBundle\Model\TrustedDeviceInterface;

interface TwoFactorAuthShopUserInterface extends TotpTwoFactorInterface, TrustedDeviceInterface
{
    public function getTotpSecret(): ?string;

    public function setTotpSecret(?string $totpSecret): void;

    public function isTwoFactorEnabled(): bool;

    public function setTwoFactorEnabled(bool $enabled): void;

    public function bumpTrustedTokenVersion(): void;
}
