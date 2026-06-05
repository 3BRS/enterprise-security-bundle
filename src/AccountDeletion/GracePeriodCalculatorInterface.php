<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

interface GracePeriodCalculatorInterface
{
    public function calculateScheduledFor(\DateTimeImmutable $now, int $gracePeriodDays): \DateTimeImmutable;
}
