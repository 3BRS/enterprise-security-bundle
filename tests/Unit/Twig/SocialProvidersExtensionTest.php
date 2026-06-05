<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Twig;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Twig\SocialProvidersExtension;
use Twig\TwigFunction;

#[CoversClass(SocialProvidersExtension::class)]
class SocialProvidersExtensionTest extends TestCase
{
    public function testGetSocialProviderNamesForAdmin(): void
    {
        $google = $this->createStub(OAuthProviderInterface::class);
        $google->method('getName')->willReturn('google');
        $apple = $this->createStub(OAuthProviderInterface::class);
        $apple->method('getName')->willReturn('apple');

        $registry = $this->createMock(OAuthProviderRegistryInterface::class);
        $registry->expects(self::once())->method('getEnabledForAdmin')->willReturn([$google, $apple]);
        $registry->expects(self::never())->method('getEnabledForCustomer');

        $extension = new SocialProvidersExtension($registry);

        self::assertSame(['google', 'apple'], $extension->getSocialProviderNames('admin'));
    }

    public function testGetSocialProviderNamesForCustomer(): void
    {
        $google = $this->createStub(OAuthProviderInterface::class);
        $google->method('getName')->willReturn('google');

        $registry = $this->createMock(OAuthProviderRegistryInterface::class);
        $registry->expects(self::once())->method('getEnabledForCustomer')->willReturn([$google]);
        $registry->expects(self::never())->method('getEnabledForAdmin');

        $extension = new SocialProvidersExtension($registry);

        self::assertSame(['google'], $extension->getSocialProviderNames('customer'));
    }

    public function testGetSocialProviderNamesReturnsEmptyWhenNoneEnabled(): void
    {
        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('getEnabledForCustomer')->willReturn([]);

        $extension = new SocialProvidersExtension($registry);

        self::assertSame([], $extension->getSocialProviderNames('customer'));
    }

    public function testGetFunctionsExposesProvidersHelper(): void
    {
        $extension = new SocialProvidersExtension($this->createStub(OAuthProviderRegistryInterface::class));

        $functions = $extension->getFunctions();

        self::assertCount(1, $functions);
        self::assertInstanceOf(TwigFunction::class, $functions[0]);
        self::assertSame('three_brs_social_providers', $functions[0]->getName());
    }
}
