<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use Symfony\Component\HttpFoundation\Request;

interface OAuthProviderInterface
{
    public function getName(): string;

    public function isEnabledForCustomer(): bool;

    public function isEnabledForAdmin(): bool;

    public function getAuthorizationUrl(string $redirectUri, string $state, string $group): string;

    public function fetchUserInfo(Request $request, string $redirectUri, string $expectedState, string $group): OAuthUserInfoInterface;
}
