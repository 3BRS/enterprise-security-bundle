<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface AutoRegistrationPolicyInterface
{
    /**
     * @param ?list<string> $allowedEmailDomains
     *     null = no domain restriction (email + verified check only),
     *     [] = no auto-registration allowed,
     *     non-empty list = only emails matching one of these domains pass.
     */
    public function canAutoRegister(OAuthUserInfoInterface $info, ?array $allowedEmailDomains): bool;
}
