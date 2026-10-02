<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\CancelPendingSignInRequiredHandler;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\PendingSignInCancellerInterface;

#[CoversClass(CancelPendingSignInRequiredHandler::class)]
class CancelPendingSignInRequiredHandlerTest extends TestCase
{
    public function testOpensTheRequestedPageAgainWhenTheSignInIsCancelled(): void
    {
        $request = Request::create('/account/orders?page=2');

        $canceller = $this->createMock(PendingSignInCancellerInterface::class);
        $canceller->expects(self::once())->method('cancelOnPageLoad')->with($request)->willReturn(true);

        $inner = $this->createMock(AuthenticationRequiredHandlerInterface::class);
        $inner->expects(self::never())->method('onAuthenticationRequired');

        $response = (new CancelPendingSignInRequiredHandler($inner, $canceller))
            ->onAuthenticationRequired($request, $this->createStub(TwoFactorTokenInterface::class));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('http://localhost/account/orders?page=2', $response->getTargetUrl());
    }

    public function testRedirectStaysOnTheHostOfTheRequest(): void
    {
        // A path beginning with "//" read back as a relative Location would leave the site.
        $request = new Request(server: [
            'HTTP_HOST' => 'shop.example',
            'REQUEST_URI' => '//evil.example/x',
        ]);

        $canceller = $this->createStub(PendingSignInCancellerInterface::class);
        $canceller->method('cancelOnPageLoad')->willReturn(true);

        $response = (new CancelPendingSignInRequiredHandler($this->createStub(AuthenticationRequiredHandlerInterface::class), $canceller))
            ->onAuthenticationRequired($request, $this->createStub(TwoFactorTokenInterface::class));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringStartsWith('http://shop.example/', $response->getTargetUrl());
    }

    public function testLeavesAKeptSignInToSchebsHandler(): void
    {
        $request = Request::create('/account/orders');
        $token = $this->createStub(TwoFactorTokenInterface::class);
        $codePage = new RedirectResponse('/2fa');

        $canceller = $this->createStub(PendingSignInCancellerInterface::class);
        $canceller->method('cancelOnPageLoad')->willReturn(false);

        $inner = $this->createMock(AuthenticationRequiredHandlerInterface::class);
        $inner->expects(self::once())->method('onAuthenticationRequired')->with($request, $token)->willReturn($codePage);

        self::assertSame($codePage, (new CancelPendingSignInRequiredHandler($inner, $canceller))->onAuthenticationRequired($request, $token));
    }
}
