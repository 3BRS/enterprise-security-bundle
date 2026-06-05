<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

class MagicLinkTokenGenerator implements MagicLinkTokenGeneratorInterface
{
    protected const TOKEN_BYTES = 32;

    public function generatePlainToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(self::TOKEN_BYTES)), '+/', '-_'), '=');
    }

    public function hash(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }
}
