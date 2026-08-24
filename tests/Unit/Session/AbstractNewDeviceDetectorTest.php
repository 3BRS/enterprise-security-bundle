<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Session\AbstractNewDeviceDetector;
use ThreeBRS\EnterpriseSecurityBundle\Session\KnownDeviceRecordInterface;

#[CoversClass(AbstractNewDeviceDetector::class)]
class AbstractNewDeviceDetectorTest extends TestCase
{
    public function testUnknownDeviceIsReportedAsNewAndRemembered(): void
    {
        $recorder = new \ArrayObject();
        $detector = $this->makeDetector($recorder);

        self::assertTrue($detector->checkAndRemember(new TestUser('user-1'), 'fingerprint-1'));
        self::assertInstanceOf(KnownDeviceRecordInterface::class, $recorder['saved']);
        self::assertSame('fingerprint-1', $recorder['saved']->getFingerprint());
        self::assertArrayNotHasKey('discarded', $recorder);
    }

    public function testKnownDeviceIsNotReportedAndNothingIsWritten(): void
    {
        $recorder = new \ArrayObject();
        $detector = $this->makeDetector($recorder, known: true);

        self::assertFalse($detector->checkAndRemember(new TestUser('user-1'), 'fingerprint-1'));
        self::assertArrayNotHasKey('saved', $recorder);
    }

    public function testConcurrentInsertIsTreatedAsAlreadyKnown(): void
    {
        // The other request won the race and is sending the notification — this one must
        // report "not new" so the user does not get a second mail for the same sign-in.
        $recorder = new \ArrayObject();
        $detector = $this->makeDetector($recorder, saveFailure: new \RuntimeException('duplicate key'), conflict: true);

        self::assertFalse($detector->checkAndRemember(new TestUser('user-1'), 'fingerprint-1'));
        self::assertInstanceOf(KnownDeviceRecordInterface::class, $recorder['discarded']);
    }

    public function testUnrelatedPersistenceFailureIsRethrown(): void
    {
        // Only a unique-key conflict means "someone else already remembered it". A dead
        // connection must not be reported to the caller as a known device.
        $failure = new \RuntimeException('connection lost');
        $detector = $this->makeDetector(new \ArrayObject(), saveFailure: $failure, conflict: false);

        $this->expectExceptionObject($failure);
        $detector->checkAndRemember(new TestUser('user-1'), 'fingerprint-1');
    }

    /**
     * @param \ArrayObject<string, mixed> $recorder
     */
    protected function makeDetector(
        \ArrayObject $recorder,
        bool $known = false,
        ?\Throwable $saveFailure = null,
        bool $conflict = false,
    ): AbstractNewDeviceDetector {
        return new class($recorder, $known, $saveFailure, $conflict) extends AbstractNewDeviceDetector {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                protected \ArrayObject $recorder,
                protected bool $known,
                protected ?\Throwable $saveFailure,
                protected bool $conflict,
            ) {
            }

            protected function isKnownDevice(UserInterface $user, string $fingerprint): bool
            {
                return $this->known;
            }

            protected function createRecord(UserInterface $user, string $fingerprint): KnownDeviceRecordInterface
            {
                $record = new class() implements KnownDeviceRecordInterface {
                    protected string $fingerprint = '';

                    public function getId(): ?int
                    {
                        return null;
                    }

                    public function getFingerprint(): string
                    {
                        return $this->fingerprint;
                    }

                    public function setFingerprint(string $fingerprint): void
                    {
                        $this->fingerprint = $fingerprint;
                    }

                    public function getCreatedAt(): \DateTimeImmutable
                    {
                        return new \DateTimeImmutable('@0');
                    }
                };
                $record->setFingerprint($fingerprint);

                return $record;
            }

            protected function save(KnownDeviceRecordInterface $record): void
            {
                if ($this->saveFailure !== null) {
                    throw $this->saveFailure;
                }

                $this->recorder['saved'] = $record;
            }

            protected function discardUnflushed(KnownDeviceRecordInterface $record): void
            {
                $this->recorder['discarded'] = $record;
            }

            protected function isConcurrentInsertConflict(\Throwable $exception): bool
            {
                return $this->conflict;
            }
        };
    }
}
