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

    public function testConsumeCountsOnlyTheUsernameByDefault(): void
    {
        // Guards the default: no companion configured means exactly the pre-existing behaviour,
        // one counter and no second settings lookup.
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->expects(self::once())
            ->method('consume')
            ->with('customer', 'login', 'user@example.com')
            ->willReturn($this->acceptedLimit())
        ;

        $guard = new RateLimitGuard($factory);

        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'user@example.com');
    }

    public function testConsumeAlsoCountsPerAddressWhenACompanionActionIsConfigured(): void
    {
        $calls = [];
        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturnCallback(
            function (string $group, string $action, string $key) use (&$calls): RateLimit {
                $calls[] = [$group, $action, $key];

                return $this->acceptedLimit();
            },
        );

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        $guard->consume(
            Request::create('/login', 'POST', server: [
                'REMOTE_ADDR' => '203.0.113.42',
            ]),
            'customer',
            'login',
            'user@example.com',
        );

        self::assertSame([
            ['customer', 'login', 'user@example.com'],
            ['customer', 'login_ip', '203.0.113.42'],
        ], $calls);
    }

    public function testConsumeSkipsTheCompanionWhenNoUsernameWasGiven(): void
    {
        // The primary counter is already keyed on the address here; counting the same request a
        // second time would silently halve the limit.
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->expects(self::once())
            ->method('consume')
            ->with('customer', 'login', '203.0.113.42')
            ->willReturn($this->acceptedLimit())
        ;

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        $guard->consume(
            Request::create('/login', 'POST', server: [
                'REMOTE_ADDR' => '203.0.113.42',
            ]),
            'customer',
            'login',
        );
    }

    public function testConsumeSkipsTheCompanionWhenItsOwnActionIsDisabled(): void
    {
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturnMap([
            ['customer', 'login', true],
            ['customer', 'login_ip', false],
        ]);
        $factory->expects(self::once())
            ->method('consume')
            ->with('customer', 'login', 'user@example.com')
            ->willReturn($this->acceptedLimit())
        ;

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'user@example.com');
    }

    public function testConsumeThrowsWhenOnlyThePerAddressCounterIsExceeded(): void
    {
        // The spraying case: every username is fresh, so the per-account counter never trips and
        // only the address counter can refuse the request.
        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturnCallback(
            fn (string $group, string $action): RateLimit => $action === 'login_ip'
                ? $this->rejectedLimit('+30 seconds')
                : $this->acceptedLimit(),
        );

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        $this->expectException(TooManyRequestsHttpException::class);
        $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'fresh@example.com');
    }

    public function testConsumeStillCountsTheAddressWhenTheUsernameCounterAlreadyTripped(): void
    {
        // Both are consumed before either verdict is acted on, so a locked-out username cannot be
        // used to shield the address counter from ever accruing.
        $calls = [];
        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturnCallback(
            function (string $group, string $action) use (&$calls): RateLimit {
                $calls[] = $action;

                return $this->rejectedLimit($action === 'login' ? '+30 seconds' : '+90 seconds');
            },
        );

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        try {
            $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'user@example.com');
            self::fail('Expected TooManyRequestsHttpException.');
        } catch (TooManyRequestsHttpException $exception) {
            // The later of the two windows wins, so the response does not invite a retry while the
            // other counter is still refusing.
            self::assertGreaterThan(60, (int) $exception->getHeaders()['Retry-After']);
        }

        self::assertSame(['login', 'login_ip'], $calls);
    }

    public function testConsumeReportsTheUsernameWindowWhenItIsTheLaterOne(): void
    {
        // Mirror of the test above with the windows swapped. Without this direction, taking the
        // companion's window unconditionally would satisfy the suite exactly as well as max() does,
        // and a client would be invited to retry while the other counter still refuses.
        $factory = $this->createStub(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturn(true);
        $factory->method('consume')->willReturnCallback(
            fn (string $group, string $action): RateLimit => $this->rejectedLimit(
                $action === 'login' ? '+90 seconds' : '+30 seconds',
            ),
        );

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        try {
            $guard->consume(Request::create('/login', 'POST'), 'customer', 'login', 'user@example.com');
            self::fail('Expected TooManyRequestsHttpException.');
        } catch (TooManyRequestsHttpException $exception) {
            self::assertGreaterThan(60, (int) $exception->getHeaders()['Retry-After']);
        }
    }

    public function testConsumeSkipsTheCompanionWhenThePrimaryActionIsDisabled(): void
    {
        // The primary action's `enabled` flag gates the whole call, companion included — the guard
        // clause at the top of consume() returns before either counter is touched.
        $factory = $this->createMock(DynamicRateLimiterFactoryInterface::class);
        $factory->method('isEnabled')->willReturnMap([
            ['customer', 'login', false],
            ['customer', 'login_ip', true],
        ]);
        $factory->expects(self::never())->method('consume');

        $guard = new RateLimitGuard($factory, [
            'login' => 'login_ip',
        ]);

        $guard->consume(
            Request::create('/login', 'POST', server: [
                'REMOTE_ADDR' => '203.0.113.42',
            ]),
            'customer',
            'login',
            'user@example.com',
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

    protected function acceptedLimit(): RateLimit
    {
        $limit = $this->createStub(RateLimit::class);
        $limit->method('isAccepted')->willReturn(true);

        return $limit;
    }

    protected function rejectedLimit(string $retryAfter): RateLimit
    {
        $limit = $this->createStub(RateLimit::class);
        $limit->method('isAccepted')->willReturn(false);
        $limit->method('getRetryAfter')->willReturn(new \DateTimeImmutable($retryAfter));

        return $limit;
    }
}
