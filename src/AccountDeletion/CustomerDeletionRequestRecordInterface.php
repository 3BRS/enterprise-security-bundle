<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

interface CustomerDeletionRequestRecordInterface
{
    public function getRequestedAt(): \DateTimeImmutable;

    public function getScheduledFor(): \DateTimeImmutable;

    public function setScheduledFor(\DateTimeImmutable $scheduledFor): void;

    public function getCancelledAt(): ?\DateTimeImmutable;

    public function setCancelledAt(?\DateTimeImmutable $cancelledAt): void;

    public function getCompletedAt(): ?\DateTimeImmutable;

    public function setCompletedAt(?\DateTimeImmutable $completedAt): void;

    public function isPending(): bool;
}
