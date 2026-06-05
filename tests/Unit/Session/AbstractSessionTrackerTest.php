<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Session\AbstractSessionTracker;
use ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\GeoIpLookupInterface;
use ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\GeoIpResult;
use ThreeBRS\EnterpriseSecurityBundle\Session\SessionRecordInterface;

#[CoversClass(AbstractSessionTracker::class)]
class AbstractSessionTrackerTest extends TestCase
{
    public function testTrackReturnsExistingWhenSessionIdAlreadyPersisted(): void
    {
        $existing = $this->createStub(SessionRecordInterface::class);
        $tracker = $this->makeTracker(findBySessionId: $existing);

        $result = $tracker->track($this->user(), 'sess-1', 'UA', '10.0.0.1');

        self::assertSame($existing, $result);
        self::assertSame(0, $tracker->saveCalls);
    }

    public function testTrackPersistsNewRecordWithGeoIp(): void
    {
        $tracker = $this->makeTracker(
            findBySessionId: null,
            geo: new GeoIpResult('US', 'New York'),
        );

        $result = $tracker->track($this->user(), 'sess-1', 'UA', '198.51.100.10');

        self::assertSame(1, $tracker->saveCalls);
        self::assertSame('sess-1', $result->getSessionId());
        self::assertSame('US', $result->getCountry());
        self::assertSame('New York', $result->getCity());
    }

    public function testTrackRetriesOnConcurrentInsertConflictAndReturnsPersisted(): void
    {
        $persisted = $this->createStub(SessionRecordInterface::class);
        // First findOneBySessionId — nothing; after concurrent conflict — returns the persisted row.
        $tracker = $this->makeTracker(
            findBySessionIdSequence: [null, $persisted],
            saveThrows: new \RuntimeException('unique conflict'),
            isConflict: true,
        );

        $result = $tracker->track($this->user(), 'sess-1', 'UA', '10.0.0.1');

        self::assertSame($persisted, $result);
        self::assertSame(1, $tracker->discardCalls);
    }

    public function testTrackRethrowsWhenSaveFailsForNonConflictReason(): void
    {
        $tracker = $this->makeTracker(
            findBySessionId: null,
            saveThrows: new \RuntimeException('disk full'),
            isConflict: false,
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('disk full');

        $tracker->track($this->user(), 'sess-1', 'UA', '10.0.0.1');
    }

    public function testTouchNoOpForNullSession(): void
    {
        $tracker = $this->makeTracker(findBySessionId: null);

        $tracker->touch('sess-missing');

        self::assertSame(0, $tracker->commitCalls);
    }

    public function testTouchNoOpForRevokedSession(): void
    {
        $revoked = $this->createStub(SessionRecordInterface::class);
        $revoked->method('isRevoked')->willReturn(true);

        $tracker = $this->makeTracker(findBySessionId: $revoked);
        $tracker->touch('sess-1');

        self::assertSame(0, $tracker->commitCalls);
    }

    public function testTouchNoOpWhenWithinThrottleWindow(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $session = $this->createMock(SessionRecordInterface::class);
        $session->method('isRevoked')->willReturn(false);
        $session->method('getLastActivityAt')->willReturn($now->modify('-30 seconds'));
        $session->expects(self::never())->method('setLastActivityAt');

        $tracker = $this->makeTracker(findBySessionId: $session, now: $now);
        $tracker->touch('sess-1');

        self::assertSame(0, $tracker->commitCalls);
    }

    public function testTouchUpdatesLastActivityWhenThrottleWindowElapsed(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $session = $this->createMock(SessionRecordInterface::class);
        $session->method('isRevoked')->willReturn(false);
        $session->method('getLastActivityAt')->willReturn($now->modify('-2 minutes'));
        $session->expects(self::once())->method('setLastActivityAt')->with($now);

        $tracker = $this->makeTracker(findBySessionId: $session, now: $now);
        $tracker->touch('sess-1');

        self::assertSame(1, $tracker->commitCalls);
    }

    public function testRevokeNoOpForAlreadyRevoked(): void
    {
        $session = $this->createMock(SessionRecordInterface::class);
        $session->method('isRevoked')->willReturn(true);
        $session->expects(self::never())->method('setRevokedAt');

        $tracker = $this->makeTracker();
        $tracker->revoke($session);

        self::assertSame(0, $tracker->commitCalls);
    }

    public function testRevokeStampsRevokedAt(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $session = $this->createMock(SessionRecordInterface::class);
        $session->method('isRevoked')->willReturn(false);
        $session->expects(self::once())->method('setRevokedAt')->with($now);

        $tracker = $this->makeTracker(now: $now);
        $tracker->revoke($session);

        self::assertSame(1, $tracker->commitCalls);
    }

    public function testRevokeOthersSkipsCurrentSession(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');

        $current = $this->createMock(SessionRecordInterface::class);
        $current->method('getSessionId')->willReturn('sess-current');
        $current->expects(self::never())->method('setRevokedAt');

        $other = $this->createMock(SessionRecordInterface::class);
        $other->method('getSessionId')->willReturn('sess-other');
        $other->expects(self::once())->method('setRevokedAt')->with($now);

        $tracker = $this->makeTracker(now: $now, activeForUser: [$current, $other]);
        $tracker->revokeOthers('sess-current', $this->user());

        self::assertSame(1, $tracker->commitCalls);
    }

    private function user(): UserInterface
    {
        return $this->createStub(UserInterface::class);
    }

    /**
     * @param ?list<?SessionRecordInterface> $findBySessionIdSequence
     * @param list<SessionRecordInterface>   $activeForUser
     *
     * @return AbstractSessionTracker&object{saveCalls: int, discardCalls: int, commitCalls: int}
     */
    private function makeTracker(
        ?SessionRecordInterface $findBySessionId = null,
        ?array $findBySessionIdSequence = null,
        ?GeoIpResult $geo = null,
        \DateTimeImmutable $now = new \DateTimeImmutable('2026-05-22 12:00:00'),
        array $activeForUser = [],
        ?\Throwable $saveThrows = null,
        bool $isConflict = false,
    ): AbstractSessionTracker {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn($now);

        $geoIp = $this->createStub(GeoIpLookupInterface::class);
        $geoIp->method('lookup')->willReturn($geo);

        return new class($geoIp, $clock, $findBySessionId, $findBySessionIdSequence, $activeForUser, $saveThrows, $isConflict) extends AbstractSessionTracker {
            public int $saveCalls = 0;

            public int $discardCalls = 0;

            public int $commitCalls = 0;

            protected int $sequenceIndex = 0;

            /**
             * @param ?list<?SessionRecordInterface>  $findBySessionIdSequence
             * @param list<SessionRecordInterface>    $activeForUser
             */
            public function __construct(
                GeoIpLookupInterface $geoIp,
                ClockInterface $clock,
                protected ?SessionRecordInterface $findBySessionId,
                protected ?array $findBySessionIdSequence,
                protected array $activeForUser,
                protected ?\Throwable $saveThrows,
                protected bool $isConflict,
            ) {
                parent::__construct($geoIp, $clock);
            }

            protected function findOneBySessionId(string $sessionId): ?SessionRecordInterface
            {
                if ($this->findBySessionIdSequence !== null) {
                    $value = $this->findBySessionIdSequence[$this->sequenceIndex] ?? null;
                    ++$this->sequenceIndex;

                    return $value;
                }

                return $this->findBySessionId;
            }

            protected function findActiveForUser(UserInterface $user): iterable
            {
                return $this->activeForUser;
            }

            protected function createNewRecord(
                UserInterface $user,
                string $sessionId,
                ?string $userAgent,
                ?string $ipAddress,
                ?string $country,
                ?string $city,
            ): SessionRecordInterface {
                $record = new class() implements SessionRecordInterface {
                    public string $sessionId = '';

                    public ?string $userAgent = null;

                    public ?string $ipAddress = null;

                    public ?string $country = null;

                    public ?string $city = null;

                    public \DateTimeImmutable $createdAt;

                    public \DateTimeImmutable $lastActivityAt;

                    public ?\DateTimeImmutable $revokedAt = null;

                    public function __construct(
                    ) {
                        $this->createdAt = new \DateTimeImmutable();
                        $this->lastActivityAt = new \DateTimeImmutable();
                    }

                    public function getSessionId(): string
                    {
                        return $this->sessionId;
                    }

                    public function setSessionId(string $sessionId): void
                    {
                        $this->sessionId = $sessionId;
                    }

                    public function getUserAgent(): ?string
                    {
                        return $this->userAgent;
                    }

                    public function setUserAgent(?string $userAgent): void
                    {
                        $this->userAgent = $userAgent;
                    }

                    public function getIpAddress(): ?string
                    {
                        return $this->ipAddress;
                    }

                    public function setIpAddress(?string $ipAddress): void
                    {
                        $this->ipAddress = $ipAddress;
                    }

                    public function getCountry(): ?string
                    {
                        return $this->country;
                    }

                    public function setCountry(?string $country): void
                    {
                        $this->country = $country;
                    }

                    public function getCity(): ?string
                    {
                        return $this->city;
                    }

                    public function setCity(?string $city): void
                    {
                        $this->city = $city;
                    }

                    public function getCreatedAt(): \DateTimeImmutable
                    {
                        return $this->createdAt;
                    }

                    public function getLastActivityAt(): \DateTimeImmutable
                    {
                        return $this->lastActivityAt;
                    }

                    public function setLastActivityAt(\DateTimeImmutable $lastActivityAt): void
                    {
                        $this->lastActivityAt = $lastActivityAt;
                    }

                    public function getRevokedAt(): ?\DateTimeImmutable
                    {
                        return $this->revokedAt;
                    }

                    public function setRevokedAt(?\DateTimeImmutable $revokedAt): void
                    {
                        $this->revokedAt = $revokedAt;
                    }

                    public function isRevoked(): bool
                    {
                        return $this->revokedAt !== null;
                    }
                };
                $record->setSessionId($sessionId);
                $record->setUserAgent($userAgent);
                $record->setIpAddress($ipAddress);
                $record->setCountry($country);
                $record->setCity($city);

                return $record;
            }

            protected function save(SessionRecordInterface $record): void
            {
                ++$this->saveCalls;
                if ($this->saveThrows !== null) {
                    throw $this->saveThrows;
                }
            }

            protected function discardUnflushed(SessionRecordInterface $record): void
            {
                ++$this->discardCalls;
            }

            protected function commit(): void
            {
                ++$this->commitCalls;
            }

            protected function isConcurrentInsertConflict(\Throwable $exception): bool
            {
                return $this->isConflict;
            }
        };
    }
}
