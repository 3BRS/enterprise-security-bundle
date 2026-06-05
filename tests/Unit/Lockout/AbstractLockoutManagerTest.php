<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Lockout;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\AbstractLockoutManager;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockableUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockoutPolicyInterface;

#[CoversClass(AbstractLockoutManager::class)]
class AbstractLockoutManagerTest extends TestCase
{
    public function testRecordFailureDoesNothingWhenFeatureDisabled(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(false);

        $user = $this->makeUser(attempts: 0);

        $manager = $this->makeManager($policy, new \DateTimeImmutable('2026-05-22 12:00:00'));
        $manager->recordFailure($user);

        self::assertSame(0, $user->failedAttempts);
        self::assertSame(0, $manager->lockCalls);
    }

    public function testRecordFailureIncrementsCounterWithinLock(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);
        $policy->method('getMaxAttempts')->willReturn(5);
        $policy->method('getAutoUnlockAfter')->willReturn(null);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 2);

        $manager = $this->makeManager($policy, $now);
        $manager->recordFailure($user);

        self::assertSame(3, $user->failedAttempts);
        self::assertSame($now, $user->lastFailedLoginAt);
        self::assertNull($user->lockedAt);
        self::assertSame(1, $manager->lockCalls);
    }

    public function testRecordFailureTriggersLockoutAtMaxAttempts(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);
        $policy->method('getMaxAttempts')->willReturn(3);
        $policy->method('getAutoUnlockAfter')->willReturn(900);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 2);

        $manager = $this->makeManager($policy, $now);
        $manager->recordFailure($user);

        self::assertSame(3, $user->failedAttempts);
        self::assertEquals($now, $user->lockedAt);
        self::assertEquals($now->modify('+900 seconds'), $user->lockoutUntil);
    }

    public function testRecordFailureResetsCounterIfPreviousLockoutExpired(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);
        $policy->method('getMaxAttempts')->willReturn(5);
        $policy->method('getAutoUnlockAfter')->willReturn(null);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        // User was locked an hour ago with a 15-minute auto-unlock — now expired.
        $user = $this->makeUser(
            attempts: 5,
            lockedAt: $now->modify('-1 hour'),
            lockoutUntil: $now->modify('-45 minutes'),
        );

        $manager = $this->makeManager($policy, $now);
        $manager->recordFailure($user);

        // Counter resets to 0 then increments to 1; previous lockout cleared.
        self::assertSame(1, $user->failedAttempts);
        self::assertNull($user->lockedAt);
        self::assertNull($user->lockoutUntil);
    }

    public function testRecordSuccessNoOpWhenAlreadyClean(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $user = $this->makeUser(attempts: 0);

        $manager = $this->makeManager($policy, new \DateTimeImmutable('2026-05-22 12:00:00'));
        $manager->recordSuccess($user);

        self::assertSame(0, $manager->commitCount);
    }

    public function testRecordSuccessResetsCountersAfterFailures(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 3, lastFailed: $now->modify('-5 minutes'));

        $manager = $this->makeManager($policy, $now);
        $manager->recordSuccess($user);

        self::assertSame(0, $user->failedAttempts);
        self::assertNull($user->lastFailedLoginAt);
        self::assertNull($user->lockedAt);
        self::assertNull($user->lockoutUntil);
        self::assertSame(1, $manager->commitCount);
    }

    public function testIsLockedFalseWhenFeatureDisabled(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(false);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 5, lockedAt: $now);

        $manager = $this->makeManager($policy, $now);

        self::assertFalse($manager->isLocked($user));
    }

    public function testIsLockedFalseWhenNeverLocked(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);

        $manager = $this->makeManager($policy, new \DateTimeImmutable('2026-05-22 12:00:00'));

        self::assertFalse($manager->isLocked($this->makeUser(attempts: 2)));
    }

    public function testIsLockedTrueWhenManualOnly(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 5, lockedAt: $now, lockoutUntil: null);

        $manager = $this->makeManager($policy, $now);

        self::assertTrue($manager->isLocked($user));
    }

    public function testIsLockedFalseAfterAutoUnlockWindowElapsed(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(
            attempts: 5,
            lockedAt: $now->modify('-1 hour'),
            lockoutUntil: $now->modify('-30 minutes'),
        );

        $manager = $this->makeManager($policy, $now);

        self::assertFalse($manager->isLocked($user));
    }

    public function testIsLockedTrueDuringAutoUnlockWindow(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $policy->method('isEnabled')->willReturn(true);

        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(
            attempts: 5,
            lockedAt: $now,
            lockoutUntil: $now->modify('+15 minutes'),
        );

        $manager = $this->makeManager($policy, $now);

        self::assertTrue($manager->isLocked($user));
    }

    public function testUnlockResetsCountersAndClearsRateLimit(): void
    {
        $policy = $this->createStub(LockoutPolicyInterface::class);
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $user = $this->makeUser(attempts: 5, lockedAt: $now);

        $manager = $this->makeManager($policy, $now);
        $manager->unlock($user);

        self::assertSame(0, $user->failedAttempts);
        self::assertNull($user->lockedAt);
        self::assertNull($user->lockoutUntil);
        self::assertSame(1, $manager->commitCount);
        self::assertSame(1, $manager->rateLimitClearCalls);
    }

    /**
     * @return AbstractLockoutManager&object{lockCalls: int, commitCount: int, rateLimitClearCalls: int}
     */
    private function makeManager(LockoutPolicyInterface $policy, \DateTimeImmutable $now): AbstractLockoutManager
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn($now);

        return new class($policy, $clock) extends AbstractLockoutManager {
            public int $lockCalls = 0;

            public int $commitCount = 0;

            public int $rateLimitClearCalls = 0;

            protected function withPessimisticLock(LockableUserInterface $user, \Closure $callback): void
            {
                ++$this->lockCalls;
                $callback();
                $this->commit();
            }

            protected function commit(): void
            {
                ++$this->commitCount;
            }

            protected function clearRateLimitForUser(LockableUserInterface $user): void
            {
                ++$this->rateLimitClearCalls;
            }
        };
    }

    /**
     * @return LockableUserInterface&object{failedAttempts: int, lastFailedLoginAt: ?\DateTimeImmutable, lockedAt: ?\DateTimeImmutable, lockoutUntil: ?\DateTimeImmutable}
     */
    private function makeUser(
        int $attempts,
        ?\DateTimeImmutable $lastFailed = null,
        ?\DateTimeImmutable $lockedAt = null,
        ?\DateTimeImmutable $lockoutUntil = null,
    ): LockableUserInterface {
        return new class($attempts, $lastFailed, $lockedAt, $lockoutUntil) implements LockableUserInterface {
            public function __construct(
                public int $failedAttempts,
                public ?\DateTimeImmutable $lastFailedLoginAt,
                public ?\DateTimeImmutable $lockedAt,
                public ?\DateTimeImmutable $lockoutUntil,
            ) {
            }

            public function getFailedLoginAttempts(): int
            {
                return $this->failedAttempts;
            }

            public function setFailedLoginAttempts(int $failedLoginAttempts): void
            {
                $this->failedAttempts = $failedLoginAttempts;
            }

            public function getLastFailedLoginAt(): ?\DateTimeImmutable
            {
                return $this->lastFailedLoginAt;
            }

            public function setLastFailedLoginAt(?\DateTimeImmutable $lastFailedLoginAt): void
            {
                $this->lastFailedLoginAt = $lastFailedLoginAt;
            }

            public function getLockedAt(): ?\DateTimeImmutable
            {
                return $this->lockedAt;
            }

            public function setLockedAt(?\DateTimeImmutable $lockedAt): void
            {
                $this->lockedAt = $lockedAt;
            }

            public function getLockoutUntil(): ?\DateTimeImmutable
            {
                return $this->lockoutUntil;
            }

            public function setLockoutUntil(?\DateTimeImmutable $lockoutUntil): void
            {
                $this->lockoutUntil = $lockoutUntil;
            }
        };
    }
}
