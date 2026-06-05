<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Lockout;

interface LockedUserRepositoryInterface
{
    /**
     * @return list<object>
     */
    public function findAllLocked(): array;
}
