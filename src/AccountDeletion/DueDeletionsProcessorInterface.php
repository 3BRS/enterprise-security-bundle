<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

interface DueDeletionsProcessorInterface
{
    /**
     * Process all deletion requests whose grace period has elapsed.
     *
     * @return int number of records processed in this run
     */
    public function process(): int;
}
