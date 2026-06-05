<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

class GracePeriodCalculator implements GracePeriodCalculatorInterface
{
    public function calculateScheduledFor(\DateTimeImmutable $now, int $gracePeriodDays): \DateTimeImmutable
    {
        if ($gracePeriodDays < 0) {
            throw new \InvalidArgumentException(sprintf('Grace period days must be non-negative, got %d.', $gracePeriodDays));
        }

        return $now->add(new \DateInterval('P' . $gracePeriodDays . 'D'));
    }
}
