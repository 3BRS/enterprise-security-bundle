<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;

/**
 * Looks up country + city for a given IP using a local MaxMind GeoLite2 / GeoIP2
 * `.mmdb` database via `geoip2/geoip2`.
 *
 * The plugin does **not** require `geoip2/geoip2` — it's listed under composer
 * `suggest`. Wire this service up only after running
 * `composer require geoip2/geoip2` in the application and providing a path to
 * a `.mmdb` file (e.g. the free GeoLite2-City download from MaxMind).
 */
class MaxMindGeoIpLookup implements GeoIpLookupInterface
{
    protected ?Reader $reader = null;

    protected bool $readerInitFailed = false;

    public function __construct(
        protected string $databasePath,
    ) {
    }

    public function lookup(?string $ipAddress): ?GeoIpResult
    {
        if ($ipAddress === null || $ipAddress === '') {
            return null;
        }

        $reader = $this->reader();
        if ($reader === null) {
            return null;
        }

        try {
            $record = $reader->city($ipAddress);
        } catch (AddressNotFoundException) {
            // IP isn't covered by the database (private ranges, unallocated blocks).
            return null;
        }

        return new GeoIpResult(
            $record->country->isoCode,
            $record->city->name,
        );
    }

    /**
     * Lazy-loads and caches the Reader instance. If construction throws — typically
     * because the configured .mmdb file is missing, unreadable, or corrupt — we
     * remember the failure for the lifetime of this service and return null on
     * every subsequent call. Geolocation is best-effort and must never block a
     * login flow because of a misconfigured GeoIP database.
     */
    protected function reader(): ?Reader
    {
        if ($this->readerInitFailed) {
            return null;
        }

        if ($this->reader === null) {
            try {
                $this->reader = new Reader($this->databasePath);
            } catch (\Throwable) {
                $this->readerInitFailed = true;

                return null;
            }
        }

        return $this->reader;
    }
}
