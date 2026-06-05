<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\RateLimit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\RateLimit;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\DynamicRateLimiterFactoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuard;

#[CoversClass(RateLimitGuard::class)]
class RateLimitGuardTest extends TestCase
{
    public function testIsEnabledDelegatesToFactory(): void
    {
        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturnMap([
            ['customer', 'login', true],
            ['admin', 'login', false],
        ]);

        $guard = new RateLimitGuard($factory);

        self::assertTrue($guard->isEnabled('customer', 'login'));
        self::assertFalse($guard->isEnabled('admin', 'login'));
    }

    public function testConsumeNoOpsWhenDisabled(): void
    {
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(false);
        $factory->expects(self::never())->method('consume');

        $guard = new RateLimitGuard($factory);

        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login');
    }

    public function testConsumeAllowsRequestWhenLimitNotExceeded(): void
    {
        $this->expectNotToPerformAssertions();

        $accepted = $this->createStub(RateLimit::class);
        $accepted->method('isAccepted')->willReturn(true);

        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturn($accepted);

        $guard = new RateLimitGuard($factory);

        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'user@example.com');
    }

    public function testConsumeThrowsWhenLimitExceeded(): void
    {
        $rejected = $this->createStub(RateLimit::class);
        $rejected->method('isAccepted')->willReturn(false);
        $rejected->method('getRetryAfter')->willReturn(new \DateTimeImmutable('+30 seconds'));

        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturn($rejected);

        $guard = new RateLimitGuard($factory);

        $this->expectException(TooManyRequestsHttpException::class);
        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login');
    }

    public function testConsumeUsesUsernameAsKeyWhenProvided(): void
    {
        $accepted = $this->createStub(RateLimit::class);
        $accepted->method('isAccepted')->willReturn(true);

        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->expects(self::once())
            ->method('consume')
            ->with('customer', 'login', 'admin@example.com')
            ->willReturn($accepted);

        $guard = new RateLimitGuard($factory);

        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'Admin@Example.com');
    }

    public function testConsumeFallsBackToClientIpWhenNoUsername(): void
    {
        $accepted = $this->createStub(RateLimit::class);
        $accepted->method('isAccepted')->willReturn(true);

        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->expects(self::once())
            ->method('consume')
            ->with('customer', 'register', '203.0.113.42')
            ->willReturn($accepted);

        $guard = new RateLimitGuard($factory);

        $guard->consume(
            Request::create('/register', 'POST', server: [
                'REMOTE_ADDR' => '203.0.113.42',
            ]),
            'customer',
            'register',
        );
    }

    public function testResetNoOpsWhenDisabled(): void
    {
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(false);
        $factory->expects(self::never())->method('reset');

        $guard = new RateLimitGuard($factory);

        $guard->reset('customer', 'login', 'user@example.com');
    }

    public function testResetLowercasesUserIdentifier(): void
    {
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->expects(self::once())
            ->method('reset')
            ->with('customer', 'login', 'admin@example.com');

        $guard = new RateLimitGuard($factory);

        $guard->reset('customer', 'login', 'Admin@Example.com');
    }
}
