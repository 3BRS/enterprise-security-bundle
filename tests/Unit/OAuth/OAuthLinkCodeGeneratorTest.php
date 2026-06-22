<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthLinkCodeGenerator;

#[CoversClass(OAuthLinkCodeGenerator::class)]
class OAuthLinkCodeGeneratorTest extends TestCase
{
    public function testGeneratesZeroPaddedSixDigitCodes(): void
    {
        $generator = new OAuthLinkCodeGenerator();

        for ($i = 0; $i < 50; ++$i) {
            self::assertMatchesRegularExpression('/^\d{6}$/', $generator->generateCode());
        }
    }

    public function testHashIsDeterministicSha256(): void
    {
        $generator = new OAuthLinkCodeGenerator();

        $expected = hash('sha256', '123456');

        self::assertSame($expected, $generator->hash('123456'));
        self::assertSame(64, strlen($generator->hash('123456')));
    }
}
