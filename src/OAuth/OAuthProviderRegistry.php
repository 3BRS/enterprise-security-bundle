<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;

class OAuthProviderRegistry implements OAuthProviderRegistryInterface
{
    /**
     * @var array<string, OAuthProviderInterface>
     */
    protected array $providers = [];

    /**
     * @param iterable<OAuthProviderInterface> $providers
     */
    public function __construct(iterable $providers)
    {
        foreach ($providers as $provider) {
            $this->providers[$provider->getName()] = $provider;
        }
    }

    public function get(string $name): OAuthProviderInterface
    {
        if (! isset($this->providers[$name])) {
            throw new OAuthProviderException(sprintf('OAuth provider "%s" is not registered.', $name));
        }

        return $this->providers[$name];
    }

    public function has(string $name): bool
    {
        return isset($this->providers[$name]);
    }

    public function getEnabledForCustomer(): array
    {
        return array_values(array_filter($this->providers, static fn (OAuthProviderInterface $p) => $p->isEnabledForCustomer()));
    }

    public function getEnabledForAdmin(): array
    {
        return array_values(array_filter($this->providers, static fn (OAuthProviderInterface $p) => $p->isEnabledForAdmin()));
    }
}
