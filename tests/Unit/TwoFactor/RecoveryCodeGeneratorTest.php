<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGenerator;

#[CoversClass(RecoveryCodeGenerator::class)]
class RecoveryCodeGeneratorTest extends TestCase
{
    public function testGeneratesRequestedNumberOfCodes(): void
    {
        $generator = new RecoveryCodeGenerator();

        $codes = $generator->generate(8);

        self::assertCount(8, $codes);
    }

    public function testGeneratedCodesAreUnique(): void
    {
        $generator = new RecoveryCodeGenerator();

        $codes = $generator->generate(20);

        self::assertSame(array_values($codes), array_values(array_unique($codes)));
    }

    public function testGeneratedCodesFollowDashedFormat(): void
    {
        $generator = new RecoveryCodeGenerator();

        $codes = $generator->generate(3);
        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/', $code);
        }
    }

    public function testThrowsOnInvalidCount(): void
    {
        $generator = new RecoveryCodeGenerator();

        $this->expectException(\InvalidArgumentException::class);
        $generator->generate(0);
    }

    public function testHashIsDeterministic(): void
    {
        $generator = new RecoveryCodeGenerator();

        self::assertSame($generator->hash('ABCDE-12345'), $generator->hash('ABCDE-12345'));
    }

    public function testHashIgnoresDashesSpacesAndCasing(): void
    {
        $generator = new RecoveryCodeGenerator();

        $canonical = $generator->hash('ABCDE12345');

        self::assertSame($canonical, $generator->hash('abcde-12345'));
        self::assertSame($canonical, $generator->hash('ABCDE 12345'));
        self::assertSame($canonical, $generator->hash('ab cde-12345'));
    }

    public function testHashDiffersBetweenCodes(): void
    {
        $generator = new RecoveryCodeGenerator();

        self::assertNotSame($generator->hash('ABCDE-12345'), $generator->hash('ABCDE-67890'));
    }

    public function testHashIsSha256HexLength(): void
    {
        $generator = new RecoveryCodeGenerator();

        self::assertSame(64, strlen($generator->hash('ABCDE-12345')));
    }
}
