<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

interface MagicLinkTokenVerifierInterface
{
    public function verify(string $plainToken): ?MagicLinkRecordInterface;
}
