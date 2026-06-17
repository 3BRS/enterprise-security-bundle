<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Symfony\Component\Security\Core\User\UserInterface;

interface PasskeyAssertionResultInterface
{
    public function getUser(): UserInterface;
}
