<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp;

interface GeoIpLookupInterface
{
    public function lookup(?string $ipAddress): ?GeoIpResult;
}
