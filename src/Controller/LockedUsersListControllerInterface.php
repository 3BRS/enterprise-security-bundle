<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Response;

interface LockedUsersListControllerInterface
{
    public function __invoke(): Response;
}
