<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface OAuthProviderRegistryInterface
{
    public function get(string $name): OAuthProviderInterface;

    public function has(string $name): bool;

    /**
     * @return list<OAuthProviderInterface>
     */
    public function getEnabledForCustomer(): array;

    /**
     * @return list<OAuthProviderInterface>
     */
    public function getEnabledForAdmin(): array;
}
