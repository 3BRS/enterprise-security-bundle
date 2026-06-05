<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorAwareAuthenticationSuccessHandler;

#[CoversClass(TwoFactorAwareAuthenticationSuccessHandler::class)]
class TwoFactorAwareAuthenticationSuccessHandlerTest extends TestCase
{
    public function testDelegatesToTwoFactorHandlerWhenTokenIsTwoFactor(): void
    {
        $request = new Request();
        $token = $this->createStub(TwoFactorTokenInterface::class);
        $response = new Response('2fa');

        $twoFactor = $this->createMock(AuthenticationRequiredHandlerInterface::class);
        $twoFactor->expects(self::once())
            ->method('onAuthenticationRequired')
            ->with($request, $token)
            ->willReturn($response);

        $default = $this->createMock(AuthenticationSuccessHandlerInterface::class);
        $default->expects(self::never())->method('onAuthenticationSuccess');

        $handler = new TwoFactorAwareAuthenticationSuccessHandler($twoFactor, $default);

        self::assertSame($response, $handler->onAuthenticationSuccess($request, $token));
    }

    public function testDelegatesToDefaultHandlerForRegularToken(): void
    {
        $request = new Request();
        $token = $this->createStub(TokenInterface::class);
        $response = new Response('ok');

        $twoFactor = $this->createMock(AuthenticationRequiredHandlerInterface::class);
        $twoFactor->expects(self::never())->method('onAuthenticationRequired');

        $default = $this->createMock(AuthenticationSuccessHandlerInterface::class);
        $default->expects(self::once())
            ->method('onAuthenticationSuccess')
            ->with($request, $token)
            ->willReturn($response);

        $handler = new TwoFactorAwareAuthenticationSuccessHandler($twoFactor, $default);

        self::assertSame($response, $handler->onAuthenticationSuccess($request, $token));
    }
}
