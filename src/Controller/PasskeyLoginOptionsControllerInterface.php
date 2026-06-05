<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface PasskeyLoginOptionsControllerInterface
{
    public function __invoke(Request $request): Response;
}
