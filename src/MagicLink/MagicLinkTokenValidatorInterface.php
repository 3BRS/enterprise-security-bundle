<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

interface MagicLinkTokenValidatorInterface
{
    public function isUsable(MagicLinkRecordInterface $token): bool;
}
