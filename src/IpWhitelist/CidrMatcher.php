<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\IpWhitelist;

use Symfony\Component\HttpFoundation\IpUtils;

class CidrMatcher implements CidrMatcherInterface
{
    public function matchesAny(string $ip, array $cidrs): bool
    {
        if ($ip === '' || $cidrs === []) {
            return false;
        }

        return IpUtils::checkIp($ip, $cidrs);
    }
}
