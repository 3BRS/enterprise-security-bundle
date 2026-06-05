<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Timing;

class DeadlineTimingPadding implements TimingPaddingInterface
{
    public function __construct(
        protected float $targetSeconds = 2.0,
    ) {
    }

    public function padTo(float $startedAt): void
    {
        $remainingSeconds = $this->targetSeconds - (microtime(true) - $startedAt);
        if ($remainingSeconds <= 0) {
            return;
        }

        usleep((int) ($remainingSeconds * 1_000_000));
    }
}
