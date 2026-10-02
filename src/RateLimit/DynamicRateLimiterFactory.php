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
    /**
     * $actionDefaults holds, per action, the values used while the settings store has no
     * `rate_limit.{action}.*` for them. A value the store does hold, `false` included, always wins.
     *
     * @param array<string, array{enabled?: bool, limit?: int, interval?: string}> $actionDefaults
     */
    public function __construct(
        protected SettingsProviderInterface $settings,
        protected StorageInterface $storage,
        protected array $actionDefaults = [],
    ) {
    }

    public function isEnabled(string $group, string $action): bool
    {
        $scope = $this->resolveScope($group);
        $path = sprintf('rate_limit.%s.enabled', $action);
        $default = $this->actionDefaults[$action]['enabled'] ?? null;

        return $default !== null && $this->settings->get($path, $scope) === null
            ? $default
            : $this->settings->getBool($path, $scope);
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
        $limitPath = sprintf('rate_limit.%s.limit', $action);
        $intervalPath = sprintf('rate_limit.%s.interval', $action);
        $defaultLimit = $this->actionDefaults[$action]['limit'] ?? null;
        $defaultInterval = $this->actionDefaults[$action]['interval'] ?? null;

        $limit = $defaultLimit !== null && $this->settings->get($limitPath, $scope) === null
            ? $defaultLimit
            : $this->settings->getInt($limitPath, $scope);
        $interval = $defaultInterval !== null && $this->settings->get($intervalPath, $scope) === null
            ? $defaultInterval
            : $this->settings->getString($intervalPath, $scope);

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
