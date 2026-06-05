<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp;

class NullGeoIpLookup implements GeoIpLookupInterface
{
    public function lookup(?string $ipAddress): ?GeoIpResult
    {
        return null;
    }
}
