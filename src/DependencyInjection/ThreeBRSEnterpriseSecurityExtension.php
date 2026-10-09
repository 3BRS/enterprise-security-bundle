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
        // The pool sits on `cache.app`, so it follows whatever backend the application gives that.
        // `cache.app` is a filesystem cache unless configured otherwise; with more than one instance
        // of the application it — or this pool — has to point at a shared backend (Redis, Memcached),
        // or each instance keeps its own counters and a client spreading its requests across them
        // gets the limit once per instance. See docs/configuration.md.
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
