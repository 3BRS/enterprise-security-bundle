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
        self::assertSame('/account/orders?page=2', $response->getTargetUrl());
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
