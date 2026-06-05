<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistry;

#[CoversClass(OAuthProviderRegistry::class)]
class OAuthProviderRegistryTest extends TestCase
{
    public function testGetReturnsRegisteredProvider(): void
    {
        $google = $this->provider('google', true, true);
        $registry = new OAuthProviderRegistry([$google]);

        self::assertSame($google, $registry->get('google'));
        self::assertTrue($registry->has('google'));
    }

    public function testGetThrowsForUnknownProvider(): void
    {
        $registry = new OAuthProviderRegistry([]);

        $this->expectException(OAuthProviderException::class);
        $registry->get('unknown');
    }

    public function testFiltersEnabledByGroup(): void
    {
        $customerOnly = $this->provider('google', customerEnabled: true, adminEnabled: false);
        $adminOnly = $this->provider('apple', customerEnabled: false, adminEnabled: true);
        $registry = new OAuthProviderRegistry([$customerOnly, $adminOnly]);

        self::assertSame([$customerOnly], $registry->getEnabledForCustomer());
        self::assertSame([$adminOnly], $registry->getEnabledForAdmin());
    }

    private function provider(string $name, bool $customerEnabled, bool $adminEnabled): OAuthProviderInterface
    {
        $provider = $this->createStub(OAuthProviderInterface::class);
        $provider->method('getName')->willReturn($name);
        $provider->method('isEnabledForCustomer')->willReturn($customerEnabled);
        $provider->method('isEnabledForAdmin')->willReturn($adminEnabled);

        return $provider;
    }
}
