<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Challenge;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ThreeBRS\EnterpriseSecurityBundle\Challenge\CodeChallengeOutcomeInterface;
use ThreeBRS\EnterpriseSecurityBundle\Challenge\CodeChallengeResult;
use ThreeBRS\EnterpriseSecurityBundle\Challenge\CodeChallengeState;
use ThreeBRS\EnterpriseSecurityBundle\Challenge\CodeChallengeValidator;

#[CoversClass(CodeChallengeValidator::class)]
#[CoversClass(CodeChallengeState::class)]
class CodeChallengeValidatorTest extends TestCase
{
    protected const NOW = 1700000000;

    protected const HASH = 'hash-of-the-correct-code';

    protected const MAX_ATTEMPTS = 5;

    public function testReportsExpiredWhenNoCodeWasEverIssued(): void
    {
        $outcome = $this->validator()->verify(
            new CodeChallengeState(null, null, 0),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::EXPIRED, $outcome->getResult());
    }

    public function testReportsExpiredWhenTheCodeHasExpired(): void
    {
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW - 1, 0),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::EXPIRED, $outcome->getResult());
    }

    public function testExpiryTakesPrecedenceOverAnOtherwiseCorrectCode(): void
    {
        // Even the right code must not link an expired challenge.
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW, 0),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::EXPIRED, $outcome->getResult());
    }

    public function testAcceptsTheCorrectCodeAndBurnsIt(): void
    {
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW + 100, 0),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::OK, $outcome->getResult());
        $this->assertBurned($outcome);
    }

    public function testRejectsAWrongCodeAndIncrementsTheAttemptCounterKeepingTheCode(): void
    {
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW + 100, 2),
            'hash-of-a-wrong-code',
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::INVALID, $outcome->getResult());
        // Code preserved so the user can try again; attempt counted.
        self::assertSame(self::HASH, $outcome->getNextState()->getHash());
        self::assertSame(self::NOW + 100, $outcome->getNextState()->getExpiresAt());
        self::assertSame(3, $outcome->getNextState()->getAttempts());
    }

    public function testTreatsAMissingSubmissionAsInvalidAndCountsTheAttempt(): void
    {
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW + 100, 0),
            null,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::INVALID, $outcome->getResult());
        self::assertSame(1, $outcome->getNextState()->getAttempts());
    }

    public function testAcceptsTheLastAllowedAttempt(): void
    {
        // maxAttempts = 5, four already spent → this is the 5th, still allowed.
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW + 100, self::MAX_ATTEMPTS - 1),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::OK, $outcome->getResult());
    }

    public function testBurnsTheCodeOnceTheAttemptLimitIsExceeded(): void
    {
        // Five already spent → this 6th guess trips the limit before the compare runs.
        $outcome = $this->validator()->verify(
            new CodeChallengeState(self::HASH, self::NOW + 100, self::MAX_ATTEMPTS),
            self::HASH,
            self::MAX_ATTEMPTS,
        );

        self::assertSame(CodeChallengeResult::TOO_MANY_ATTEMPTS, $outcome->getResult());
        $this->assertBurned($outcome);
    }

    protected function assertBurned(CodeChallengeOutcomeInterface $outcome): void
    {
        self::assertNull($outcome->getNextState()->getHash());
        self::assertNull($outcome->getNextState()->getExpiresAt());
        self::assertSame(0, $outcome->getNextState()->getAttempts());
    }

    protected function validator(): CodeChallengeValidator
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable('@' . self::NOW));

        return new CodeChallengeValidator($clock);
    }
}
