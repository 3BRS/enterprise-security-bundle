<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\AccountDeletion;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\NullLogger;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\AbstractDueDeletionsProcessor;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\CustomerDeletionRequestRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\CustomerDeletionRequestRepositoryInterface;

#[CoversClass(AbstractDueDeletionsProcessor::class)]
class AbstractDueDeletionsProcessorTest extends TestCase
{
    public function testProcessNoDueRequests(): void
    {
        $repository = $this->createStub(CustomerDeletionRequestRepositoryInterface::class);
        $repository->method('findDue')->willReturn([]);

        $processor = $this->makeProcessor($repository, new \DateTimeImmutable('2026-05-22 12:00:00'));

        self::assertSame(0, $processor->process());
        self::assertSame([], $processor->anonymizedRecords);
    }

    public function testProcessTwoDueRequests(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $r1 = $this->createMock(CustomerDeletionRequestRecordInterface::class);
        $r1->expects(self::once())->method('setCompletedAt')->with($now);
        $r2 = $this->createMock(CustomerDeletionRequestRecordInterface::class);
        $r2->expects(self::once())->method('setCompletedAt')->with($now);

        $repository = $this->createStub(CustomerDeletionRequestRepositoryInterface::class);
        $repository->method('findDue')->willReturn([$r1, $r2]);

        $processor = $this->makeProcessor($repository, $now);

        self::assertSame(2, $processor->process());
        self::assertSame([$r1, $r2], $processor->anonymizedRecords);
        self::assertSame(2, $processor->commitCount);
    }

    public function testBeforeAnonymizeFailureIsLoggedAndAnonymizeStillRuns(): void
    {
        $now = new \DateTimeImmutable('2026-05-22 12:00:00');
        $r1 = $this->createStub(CustomerDeletionRequestRecordInterface::class);

        $repository = $this->createStub(CustomerDeletionRequestRepositoryInterface::class);
        $repository->method('findDue')->willReturn([$r1]);

        $processor = $this->makeProcessor($repository, $now, throwInBeforeAnonymize: true);

        self::assertSame(1, $processor->process());
        // Pre-anonymize threw → caught + logged → anonymize still happens.
        self::assertSame([$r1], $processor->anonymizedRecords);
        self::assertSame(1, $processor->commitCount);
    }

    /**
     * @return AbstractDueDeletionsProcessor&object{anonymizedRecords: list<CustomerDeletionRequestRecordInterface>, commitCount: int}
     */
    private function makeProcessor(
        CustomerDeletionRequestRepositoryInterface $repository,
        \DateTimeImmutable $now,
        bool $throwInBeforeAnonymize = false,
    ): AbstractDueDeletionsProcessor {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn($now);

        return new class($repository, $clock, $throwInBeforeAnonymize) extends AbstractDueDeletionsProcessor {
            /**
             * @var list<CustomerDeletionRequestRecordInterface>
             */
            public array $anonymizedRecords = [];

            public int $commitCount = 0;

            public function __construct(
                CustomerDeletionRequestRepositoryInterface $repository,
                ClockInterface $clock,
                protected bool $throwInBeforeAnonymize,
            ) {
                parent::__construct($repository, $clock, new NullLogger());
            }

            protected function onBeforeAnonymize(CustomerDeletionRequestRecordInterface $request): void
            {
                if ($this->throwInBeforeAnonymize) {
                    throw new \RuntimeException('email send failed');
                }
            }

            protected function anonymize(CustomerDeletionRequestRecordInterface $request): void
            {
                $this->anonymizedRecords[] = $request;
            }

            protected function commit(): void
            {
                ++$this->commitCount;
            }
        };
    }
}
