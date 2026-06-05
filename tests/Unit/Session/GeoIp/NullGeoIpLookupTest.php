<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session\GeoIp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\NullGeoIpLookup;

#[CoversClass(NullGeoIpLookup::class)]
class NullGeoIpLookupTest extends TestCase
{
    public function testAlwaysReturnsNull(): void
    {
        $lookup = new NullGeoIpLookup();

        self::assertNull($lookup->lookup(null));
        self::assertNull($lookup->lookup(''));
        self::assertNull($lookup->lookup('8.8.8.8'));
        self::assertNull($lookup->lookup('2001:db8::1'));
    }
}
