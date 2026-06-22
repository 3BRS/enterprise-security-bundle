<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface OAuthLinkCodeGeneratorInterface
{
    public function generateCode(): string;

    public function hash(string $plainCode): string;
}
