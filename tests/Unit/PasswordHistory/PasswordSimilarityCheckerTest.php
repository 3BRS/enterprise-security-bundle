<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\PasswordHistory;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\PasswordHistory\PasswordSimilarityChecker;

#[CoversClass(PasswordSimilarityChecker::class)]
class PasswordSimilarityCheckerTest extends TestCase
{
    public function testExactMatchIsSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertTrue($checker->isSimilar('Heslo123!', 'Heslo123!'));
    }

    public function testShorterContainedInLongerIsSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertTrue($checker->isSimilar('1234', '12345'));
    }

    public function testLongerContainingShorterIsSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertTrue($checker->isSimilar('12345', '1234'));
    }

    public function testUnrelatedPasswordsAreNotSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertFalse($checker->isSimilar('Heslo123!', 'UplneJine'));
    }

    public function testAnagramsAreNotSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertFalse($checker->isSimilar('adampoclar', 'poclaradam'));
    }

    public function testEmptyStringIsNotSimilarToAnything(): void
    {
        $checker = new PasswordSimilarityChecker();

        self::assertFalse($checker->isSimilar('', 'Heslo123!'));
        self::assertFalse($checker->isSimilar('Heslo123!', ''));
        self::assertFalse($checker->isSimilar('', ''));
    }

    public function testSingleCharEditIsNotSimilar(): void
    {
        $checker = new PasswordSimilarityChecker();

        // Containment only — single char swap with different chars on both
        // sides is not a substring relation.
        self::assertFalse($checker->isSimilar('Heslo1!', 'Heslo2!'));
    }
}
