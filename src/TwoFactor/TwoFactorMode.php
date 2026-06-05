<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

enum TwoFactorMode: string
{
    case DISABLED = 'disabled';
    case ALLOWED = 'allowed';
    case ENFORCED = 'enforced';

    public function isDisabled(): bool
    {
        return $this === self::DISABLED;
    }

    public function isEnforced(): bool
    {
        return $this === self::ENFORCED;
    }
}
