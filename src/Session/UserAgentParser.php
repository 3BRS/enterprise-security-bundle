<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

use DeviceDetector\DeviceDetector;

class UserAgentParser implements UserAgentParserInterface
{
    public function parse(?string $userAgent): UserAgentInfo
    {
        if ($userAgent === null || $userAgent === '') {
            return new UserAgentInfo(null, null, null);
        }

        $detector = new DeviceDetector($userAgent);
        $detector->parse();

        $browser = $detector->getClient('name');
        $os = $detector->getOs('name');
        $deviceName = $detector->getDeviceName();

        return new UserAgentInfo(
            $this->stringOrNull($browser),
            $this->stringOrNull($os),
            $deviceName === '' ? null : $deviceName,
        );
    }

    protected function stringOrNull(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        return $value === '' ? null : $value;
    }
}
