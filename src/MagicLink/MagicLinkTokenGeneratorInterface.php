<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

interface MagicLinkTokenGeneratorInterface
{
    public function generatePlainToken(): string;

    public function hash(string $plainToken): string;
}
