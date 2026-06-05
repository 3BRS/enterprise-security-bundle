<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Session\SessionFingerprintGenerator;

#[CoversClass(SessionFingerprintGenerator::class)]
class SessionFingerprintGeneratorTest extends TestCase
{
    public function testSameInputsProduceSameFingerprint(): void
    {
        $generator = new SessionFingerprintGenerator();

        self::assertSame(
            $generator->generate('Mozilla/5.0', '127.0.0.1'),
            $generator->generate('Mozilla/5.0', '127.0.0.1'),
        );
    }

    public function testDifferentUserAgentChangesFingerprint(): void
    {
        $generator = new SessionFingerprintGenerator();

        self::assertNotSame(
            $generator->generate('Mozilla/5.0', '127.0.0.1'),
            $generator->generate('Other UA', '127.0.0.1'),
        );
    }

    public function testDifferentIpChangesFingerprint(): void
    {
        $generator = new SessionFingerprintGenerator();

        self::assertNotSame(
            $generator->generate('Mozilla/5.0', '127.0.0.1'),
            $generator->generate('Mozilla/5.0', '203.0.113.1'),
        );
    }

    public function testNullInputsAreAccepted(): void
    {
        $generator = new SessionFingerprintGenerator();

        $fp = $generator->generate(null, null);
        self::assertNotSame('', $fp);
        self::assertSame(64, strlen($fp));
    }
}
