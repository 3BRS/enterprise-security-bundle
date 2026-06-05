<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Timing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Timing\DeadlineTimingPadding;

#[CoversClass(DeadlineTimingPadding::class)]
class DeadlineTimingPaddingTest extends TestCase
{
    public function testReturnsImmediatelyWhenDeadlineAlreadyPassed(): void
    {
        $padding = new DeadlineTimingPadding(targetSeconds: 0.1);

        // Pretend we started a long time ago — the deadline is already past, so padTo() should not sleep.
        $startedAt = microtime(true) - 10.0;
        $before = microtime(true);
        $padding->padTo($startedAt);
        $elapsed = microtime(true) - $before;

        self::assertLessThan(0.05, $elapsed);
    }

    public function testWaitsUntilTargetDeadlineWhenWorkFinishedEarly(): void
    {
        $padding = new DeadlineTimingPadding(targetSeconds: 0.2);

        $startedAt = microtime(true);
        $padding->padTo($startedAt);
        $totalElapsed = microtime(true) - $startedAt;

        // Allow scheduling jitter (~10ms) on either side of the 0.2s target.
        self::assertGreaterThanOrEqual(0.19, $totalElapsed);
        self::assertLessThan(0.35, $totalElapsed);
    }
}
