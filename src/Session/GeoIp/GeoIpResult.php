<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp;

class GeoIpResult
{
    public function __construct(
        public readonly ?string $countryCode,
        public readonly ?string $city,
    ) {
    }
}
