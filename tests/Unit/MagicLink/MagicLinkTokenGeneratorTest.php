<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\MagicLink;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenGenerator;

#[CoversClass(MagicLinkTokenGenerator::class)]
class MagicLinkTokenGeneratorTest extends TestCase
{
    public function testGeneratedTokensAreUrlSafeAndUnique(): void
    {
        $generator = new MagicLinkTokenGenerator();

        $first = $generator->generatePlainToken();
        $second = $generator->generatePlainToken();

        self::assertNotSame($first, $second);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $first);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $second);
        self::assertGreaterThanOrEqual(32, strlen($first));
    }

    public function testHashIsDeterministicSha256(): void
    {
        $generator = new MagicLinkTokenGenerator();

        $plain = 'some-token';
        $expected = hash('sha256', $plain);

        self::assertSame($expected, $generator->hash($plain));
        self::assertSame(64, strlen($generator->hash($plain)));
    }
}
