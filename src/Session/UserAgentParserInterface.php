<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

interface UserAgentParserInterface
{
    public function parse(?string $userAgent): UserAgentInfo;
}
