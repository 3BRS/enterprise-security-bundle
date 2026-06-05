<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

interface CustomerDeletionRequestRepositoryInterface
{
    /**
     * @return list<CustomerDeletionRequestRecordInterface>
     */
    public function findPendingForAdmin(): array;

    /**
     * Returns all requests whose grace period has elapsed (scheduledFor <= $now)
     * and that have not been cancelled or completed yet. Used by the scheduler
     * to drive periodic anonymisation.
     *
     * @return list<CustomerDeletionRequestRecordInterface>
     */
    public function findDue(\DateTimeImmutable $now): array;
}
