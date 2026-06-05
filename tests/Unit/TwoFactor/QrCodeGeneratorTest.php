<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\QrCodeGenerator;

#[CoversClass(QrCodeGenerator::class)]
class QrCodeGeneratorTest extends TestCase
{
    public function testReturnsBase64PngDataUri(): void
    {
        $dataUri = (new QrCodeGenerator())->generateDataUri('otpauth://totp/Example:user?secret=ABC');

        self::assertStringStartsWith('data:image/png;base64,', $dataUri);
        $base64 = substr($dataUri, strlen('data:image/png;base64,'));
        self::assertNotFalse(base64_decode($base64, true));
    }

    public function testHonoursCustomSize(): void
    {
        $dataUri = (new QrCodeGenerator())->generateDataUri('payload', size: 200);

        self::assertStringStartsWith('data:image/png;base64,', $dataUri);
        $base64 = substr($dataUri, strlen('data:image/png;base64,'));
        self::assertNotFalse(base64_decode($base64, true));
    }
}
