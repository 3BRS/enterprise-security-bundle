<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

class OAuthLinkCodeGenerator implements OAuthLinkCodeGeneratorInterface
{
    protected const CODE_DIGITS = 6;

    public function generateCode(): string
    {
        $max = (10 ** self::CODE_DIGITS) - 1;

        return str_pad((string) random_int(0, $max), self::CODE_DIGITS, '0', STR_PAD_LEFT);
    }

    public function hash(string $plainCode): string
    {
        return hash('sha256', $plainCode);
    }
}
