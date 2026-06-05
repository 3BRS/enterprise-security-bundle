<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

class SessionFingerprintGenerator implements SessionFingerprintGeneratorInterface
{
    public function generate(?string $userAgent, ?string $ipAddress): string
    {
        return hash('sha256', sprintf('%s|%s', $userAgent ?? '', $ipAddress ?? ''));
    }
}
