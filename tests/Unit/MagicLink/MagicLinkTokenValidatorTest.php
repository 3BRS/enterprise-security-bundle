<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\MagicLink;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenValidator;

#[CoversClass(MagicLinkTokenValidator::class)]
class MagicLinkTokenValidatorTest extends TestCase
{
    public function testReturnsFalseWhenAlreadyUsed(): void
    {
        $validator = new MagicLinkTokenValidator($this->fixedClock('2026-01-01 12:00:00'));

        $token = $this->createStub(MagicLinkRecordInterface::class);
        $token->method('getUsedAt')->willReturn(new \DateTimeImmutable('2026-01-01 11:00:00'));
        $token->method('getExpiresAt')->willReturn(new \DateTimeImmutable('2026-01-01 13:00:00'));

        self::assertFalse($validator->isUsable($token));
    }

    public function testReturnsFalseWhenExpired(): void
    {
        $validator = new MagicLinkTokenValidator($this->fixedClock('2026-01-01 12:00:00'));

        $token = $this->createStub(MagicLinkRecordInterface::class);
        $token->method('getUsedAt')->willReturn(null);
        $token->method('getExpiresAt')->willReturn(new \DateTimeImmutable('2026-01-01 11:59:59'));

        self::assertFalse($validator->isUsable($token));
    }

    public function testReturnsTrueWhenUnusedAndNotExpired(): void
    {
        $validator = new MagicLinkTokenValidator($this->fixedClock('2026-01-01 12:00:00'));

        $token = $this->createStub(MagicLinkRecordInterface::class);
        $token->method('getUsedAt')->willReturn(null);
        $token->method('getExpiresAt')->willReturn(new \DateTimeImmutable('2026-01-01 12:00:01'));

        self::assertTrue($validator->isUsable($token));
    }

    public function testReturnsTrueWhenExpiringExactlyNow(): void
    {
        $validator = new MagicLinkTokenValidator($this->fixedClock('2026-01-01 12:00:00'));

        $token = $this->createStub(MagicLinkRecordInterface::class);
        $token->method('getUsedAt')->willReturn(null);
        $token->method('getExpiresAt')->willReturn(new \DateTimeImmutable('2026-01-01 12:00:00'));

        self::assertTrue($validator->isUsable($token));
    }

    protected function fixedClock(string $datetime): ClockInterface
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable($datetime));

        return $clock;
    }
}
