<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\IpWhitelist;

interface CidrMatcherInterface
{
    /**
     * @param list<string> $cidrs
     */
    public function matchesAny(string $ip, array $cidrs): bool;
}
