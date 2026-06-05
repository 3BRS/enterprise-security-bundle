<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Lockout;

class LockoutPolicy implements LockoutPolicyInterface
{
    public function __construct(
        protected bool $enabled,
        protected int $maxAttempts,
        protected ?int $autoUnlockAfter,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getMaxAttempts(): int
    {
        return $this->maxAttempts;
    }

    public function getAutoUnlockAfter(): ?int
    {
        return $this->autoUnlockAfter;
    }
}
