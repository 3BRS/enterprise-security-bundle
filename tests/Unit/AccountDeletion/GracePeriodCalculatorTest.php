<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\AccountDeletion;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\GracePeriodCalculator;

#[CoversClass(GracePeriodCalculator::class)]
class GracePeriodCalculatorTest extends TestCase
{
    public function testAddsConfiguredDaysToNow(): void
    {
        $calculator = new GracePeriodCalculator();

        $scheduled = $calculator->calculateScheduledFor(new \DateTimeImmutable('2026-05-17 12:00:00'), 30);

        self::assertSame('2026-06-16 12:00:00', $scheduled->format('Y-m-d H:i:s'));
    }

    public function testZeroDaysReturnsSameMoment(): void
    {
        $calculator = new GracePeriodCalculator();

        $now = new \DateTimeImmutable('2026-05-17 12:00:00');
        $scheduled = $calculator->calculateScheduledFor($now, 0);

        self::assertEquals($now, $scheduled);
    }

    public function testRejectsNegativeDays(): void
    {
        $calculator = new GracePeriodCalculator();

        $this->expectException(\InvalidArgumentException::class);
        $calculator->calculateScheduledFor(new \DateTimeImmutable('2026-05-17 12:00:00'), -1);
    }
}
