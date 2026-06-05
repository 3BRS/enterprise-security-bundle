<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Timing;

interface TimingPaddingInterface
{
    public function padTo(float $startedAt): void;
}
