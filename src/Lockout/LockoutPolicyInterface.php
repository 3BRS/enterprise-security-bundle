<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Lockout;

interface LockoutPolicyInterface
{
    public function isEnabled(): bool;

    public function getMaxAttempts(): int;

    public function getAutoUnlockAfter(): ?int;
}
