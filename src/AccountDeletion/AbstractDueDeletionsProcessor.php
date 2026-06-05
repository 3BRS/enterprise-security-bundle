<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Scheduler loop for GDPR self-service account deletion. Loads requests whose
 * grace period has elapsed, runs pre-anonymize hook (typically a completion
 * email), anonymizes the underlying user data, stamps `completedAt`, and
 * commits the change set. Subclass plugs in the framework-specific anonymize
 * + commit + email steps.
 *
 * Designed to be invoked from a cron job (e.g. a Symfony console command).
 * Returns the number of records processed in one run so the operator can log
 * progress / wire alerting against unprocessed backlogs.
 */
abstract class AbstractDueDeletionsProcessor implements DueDeletionsProcessorInterface
{
    protected LoggerInterface $logger;

    public function __construct(
        protected CustomerDeletionRequestRepositoryInterface $repository,
        protected ClockInterface $clock,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function process(): int
    {
        $now = $this->clock->now();
        $processed = 0;

        foreach ($this->repository->findDue($now) as $request) {
            // Pre-anonymize hook is best-effort (typically sends a completion
            // email). The customer's PII is about to be erased — a transient
            // SMTP failure must not block the deletion itself, otherwise the
            // PII would linger because of an external system fault.
            try {
                $this->onBeforeAnonymize($request);
            } catch (\Throwable $exception) {
                $this->logger->warning('three_brs.account_deletion.completion_hook_failed', [
                    'reason' => $exception->getMessage(),
                ]);
            }

            $this->anonymize($request);
            $request->setCompletedAt($now);
            $this->commit();
            ++$processed;
        }

        return $processed;
    }

    /**
     * Pre-anonymize step, typically sending the "your account has been deleted"
     * email while the user record still has identifying data. Exceptions are
     * caught + logged by the loop above.
     */
    abstract protected function onBeforeAnonymize(CustomerDeletionRequestRecordInterface $request): void;

    /**
     * Replace identifying fields on the underlying user record with
     * non-identifying placeholders. Implementation owns persistence semantics
     * (call your `UserAnonymizerInterface` impl, mutate the entity, …).
     */
    abstract protected function anonymize(CustomerDeletionRequestRecordInterface $request): void;

    /**
     * Persist the changes made by the current iteration (typically `$entityManager->flush()`).
     */
    abstract protected function commit(): void;
}
