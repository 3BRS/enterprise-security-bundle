<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

use Psr\Clock\ClockInterface;

class MagicLinkTokenValidator implements MagicLinkTokenValidatorInterface
{
    public function __construct(
        protected ClockInterface $clock,
    ) {
    }

    public function isUsable(MagicLinkRecordInterface $token): bool
    {
        if ($token->getUsedAt() !== null) {
            return false;
        }

        return $token->getExpiresAt() >= $this->clock->now();
    }
}
