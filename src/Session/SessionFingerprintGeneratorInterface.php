<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

interface SessionFingerprintGeneratorInterface
{
    public function generate(?string $userAgent, ?string $ipAddress): string;
}
