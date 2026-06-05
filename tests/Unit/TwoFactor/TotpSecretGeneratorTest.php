<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use OTPHP\TOTP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TotpSecretGenerator;

#[CoversClass(TotpSecretGenerator::class)]
class TotpSecretGeneratorTest extends TestCase
{
    public function testGeneratedSecretIsNonEmpty(): void
    {
        $generator = new TotpSecretGenerator();

        $secret = $generator->generateSecret();

        self::assertNotSame('', $secret);
    }

    public function testGeneratedSecretsAreUnique(): void
    {
        $generator = new TotpSecretGenerator();

        self::assertNotSame($generator->generateSecret(), $generator->generateSecret());
    }

    public function testBuildProvisioningUriIncludesIssuerAndUsername(): void
    {
        $generator = new TotpSecretGenerator();
        $secret = $generator->generateSecret();

        $uri = $generator->buildProvisioningUri($secret, 'alice@example.com', 'My Store');

        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertStringContainsString('alice%40example.com', $uri);
        self::assertStringContainsString('issuer=My%20Store', $uri);
        self::assertStringContainsString('secret=' . $secret, $uri);
    }

    public function testVerifyCodeAcceptsValidCurrentCode(): void
    {
        $generator = new TotpSecretGenerator();
        $secret = $generator->generateSecret();
        $currentCode = TOTP::createFromSecret($secret)->now();

        self::assertTrue($generator->verifyCode($secret, $currentCode));
    }

    public function testVerifyCodeRejectsInvalidCode(): void
    {
        $generator = new TotpSecretGenerator();
        $secret = $generator->generateSecret();

        self::assertFalse($generator->verifyCode($secret, '000000'));
    }
}
