<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\RateLimit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\DynamicRateLimiterFactory;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(DynamicRateLimiterFactory::class)]
class DynamicRateLimiterFactoryTest extends TestCase
{
    public function testIsEnabledReadsFromSettingsForCustomerScope(): void
    {
        $settings = $this->createMock(SettingsProviderInterface::class);
        $settings->expects(self::once())
            ->method('getBool')
            ->with('rate_limit.login.enabled', SettingsScope::CUSTOMER)
            ->willReturn(true);

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        self::assertTrue($factory->isEnabled('customer', 'login'));
    }

    public function testIsEnabledReadsFromSettingsForAdminScope(): void
    {
        $settings = $this->createMock(SettingsProviderInterface::class);
        $settings->expects(self::once())
            ->method('getBool')
            ->with('rate_limit.login.enabled', SettingsScope::ADMIN)
            ->willReturn(false);

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        self::assertFalse($factory->isEnabled('admin', 'login'));
    }

    public function testConsumeAcceptsWhenLimitNotExceeded(): void
    {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturn(true);
        $settings->method('getInt')->willReturn(5);
        $settings->method('getString')->willReturn('15 minutes');

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        $limit = $factory->consume('customer', 'login', 'user@example.com');

        self::assertTrue($limit->isAccepted());
    }

    public function testConsumeRejectsAfterLimitReached(): void
    {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturn(true);
        $settings->method('getInt')->willReturn(2);
        $settings->method('getString')->willReturn('15 minutes');

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        self::assertTrue($factory->consume('customer', 'login', 'a@b.com')->isAccepted());
        self::assertTrue($factory->consume('customer', 'login', 'a@b.com')->isAccepted());
        self::assertFalse($factory->consume('customer', 'login', 'a@b.com')->isAccepted());
    }

    public function testResetClearsExistingCounter(): void
    {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturn(true);
        $settings->method('getInt')->willReturn(1);
        $settings->method('getString')->willReturn('15 minutes');

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        self::assertTrue($factory->consume('customer', 'login', 'a@b.com')->isAccepted());
        self::assertFalse($factory->consume('customer', 'login', 'a@b.com')->isAccepted());

        $factory->reset('customer', 'login', 'a@b.com');

        self::assertTrue($factory->consume('customer', 'login', 'a@b.com')->isAccepted());
    }

    public function testDifferentScopesGetIndependentBuckets(): void
    {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturn(true);
        $settings->method('getInt')->willReturn(1);
        $settings->method('getString')->willReturn('15 minutes');

        $factory = new DynamicRateLimiterFactory($settings, new InMemoryStorage());

        // Same key under different (group, action) tuples must not collide.
        self::assertTrue($factory->consume('customer', 'login', 'shared@key.com')->isAccepted());
        self::assertTrue($factory->consume('admin', 'login', 'shared@key.com')->isAccepted());
    }
}
