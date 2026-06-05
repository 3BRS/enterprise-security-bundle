<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class ThreeBRSEnterpriseSecurityExtension extends Extension implements PrependExtensionInterface
{
    public function prepend(ContainerBuilder $container): void
    {
        // Dedicated cache pool for the dynamic rate limiter. Symfony's default
        // `cache.rate_limiter` pool is only auto-created when `framework.rate_limiter`
        // is configured — we don't use Symfony's compile-time limiter registration
        // (DynamicRateLimiterFactory builds limiters at request time from DB-backed
        // settings), so the bundle ships its own pool and pins the storage to it.
        //
        // We back it with `cache.app` (not `cache.adapter.filesystem`) because
        // multi-pod deployments (Kubernetes, autoscaled containers) do not share
        // a filesystem — each pod would have its own counters and an attacker
        // could just retry on a different replica to bypass the limit. In a
        // single-instance deployment cache.app defaults to filesystem and the
        // behaviour is identical; in a clustered setup the app already needs
        // cache.app pointing at a shared backend (Redis / Memcached) for
        // Symfony's session, doctrine cache, etc. — we piggyback on that.
        $container->prependExtensionConfig('framework', [
            'cache' => [
                'pools' => [
                    'three_brs.rate_limiter.cache_pool' => [
                        'adapter' => 'cache.app',
                    ],
                ],
            ],
        ]);
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }

    public function getAlias(): string
    {
        return 'three_brs_enterprise_security';
    }
}
