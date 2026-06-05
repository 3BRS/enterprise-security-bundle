<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\RateLimit;

use Symfony\Component\RateLimiter\RateLimit;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\StorageInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class DynamicRateLimiterFactory implements DynamicRateLimiterFactoryInterface
{
    public function __construct(
        protected SettingsProviderInterface $settings,
        protected StorageInterface $storage,
    ) {
    }

    public function isEnabled(string $group, string $action): bool
    {
        return $this->settings->getBool(
            sprintf('rate_limit.%s.enabled', $action),
            $this->resolveScope($group),
        );
    }

    public function consume(string $group, string $action, string $key): RateLimit
    {
        return $this->buildFactory($group, $action)->create($key)->consume();
    }

    public function reset(string $group, string $action, string $key): void
    {
        $this->buildFactory($group, $action)->create($key)->reset();
    }

    protected function buildFactory(string $group, string $action): RateLimiterFactory
    {
        $scope = $this->resolveScope($group);
        $limit = $this->settings->getInt(sprintf('rate_limit.%s.limit', $action), $scope);
        $interval = $this->settings->getString(sprintf('rate_limit.%s.interval', $action), $scope);

        return new RateLimiterFactory(
            [
                'id' => sprintf('three_brs_%s_%s', $group, $action),
                'policy' => 'fixed_window',
                'limit' => $limit,
                'interval' => $interval,
            ],
            $this->storage,
        );
    }

    protected function resolveScope(string $group): SettingsScope
    {
        return match ($group) {
            'customer' => SettingsScope::CUSTOMER,
            'admin' => SettingsScope::ADMIN,
            default => throw new \InvalidArgumentException(sprintf(
                'Unknown rate limit group "%s"; expected "customer" or "admin".',
                $group,
            )),
        };
    }
}
