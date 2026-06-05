<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session\GeoIp;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use GeoIp2\Model\City;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\MaxMindGeoIpLookup;

#[CoversClass(MaxMindGeoIpLookup::class)]
class MaxMindGeoIpLookupTest extends TestCase
{
    public function testReturnsNullForEmptyIp(): void
    {
        $lookup = new MaxMindGeoIpLookup('/nonexistent.mmdb');

        self::assertNull($lookup->lookup(null));
        self::assertNull($lookup->lookup(''));
    }

    public function testReturnsNullWhenAddressNotFoundInDatabase(): void
    {
        $reader = $this->createStub(Reader::class);
        $reader->method('city')->willThrowException(new AddressNotFoundException('not in db'));

        $lookup = $this->buildLookupWithReader($reader);

        self::assertNull($lookup->lookup('10.0.0.1'));
    }

    public function testReturnsCountryAndCityFromDatabase(): void
    {
        $cityModel = new City([
            'country' => [
                'iso_code' => 'CZ',
            ],
            'city' => [
                'names' => [
                    'en' => 'Prague',
                ],
            ],
        ], ['en']);

        $reader = $this->createMock(Reader::class);
        $reader->expects(self::once())->method('city')->with('1.2.3.4')->willReturn($cityModel);

        $lookup = $this->buildLookupWithReader($reader);
        $result = $lookup->lookup('1.2.3.4');

        self::assertNotNull($result);
        self::assertSame('CZ', $result->countryCode);
        self::assertSame('Prague', $result->city);
    }

    protected function buildLookupWithReader(Reader $reader): MaxMindGeoIpLookup
    {
        return new class($reader) extends MaxMindGeoIpLookup {
            public function __construct(
                protected Reader $injected,
            ) {
                parent::__construct('/nonexistent.mmdb');
            }

            protected function reader(): Reader
            {
                return $this->injected;
            }
        };
    }
}
