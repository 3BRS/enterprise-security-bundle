<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\CustomAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\HttpUtils;
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

    public function testRedirectsToTheFirewallsDefaultTargetPath(): void
    {
        $handler = $this->configuredByTheFirewall(new DefaultAuthenticationSuccessHandler(new HttpUtils()), [
            'default_target_path' => '/account',
        ]);

        $response = $handler->onAuthenticationSuccess($this->signInRequest(), $this->createStub(TokenInterface::class));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('http://localhost/account', $response->getTargetUrl());
    }

    public function testReturnsToThePageSavedForTheFirewall(): void
    {
        $handler = $this->configuredByTheFirewall(new DefaultAuthenticationSuccessHandler(new HttpUtils()), [
            'default_target_path' => '/account',
        ]);
        $request = $this->signInRequest();
        $request->getSession()->set('_security.shop.target_path', 'http://localhost/account/orders');

        $response = $handler->onAuthenticationSuccess($request, $this->createStub(TokenInterface::class));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('http://localhost/account/orders', $response->getTargetUrl());
    }

    public function testConfiguresACopyOfTheSharedWrappedHandler(): void
    {
        $shared = new DefaultAuthenticationSuccessHandler(new HttpUtils());

        $this->configuredByTheFirewall($shared, [
            'default_target_path' => '/account',
        ]);

        self::assertSame('/', $shared->getOptions()['default_target_path']);
        self::assertNull($shared->getFirewallName());
    }

    public function testKeepsAWrappedHandlerThatTakesNoOptions(): void
    {
        $request = $this->signInRequest();
        $token = $this->createStub(TokenInterface::class);
        $response = new Response('ok');

        $default = $this->createMock(AuthenticationSuccessHandlerInterface::class);
        $default->expects(self::once())
            ->method('onAuthenticationSuccess')
            ->with($request, $token)
            ->willReturn($response);

        $handler = $this->configuredByTheFirewall($default, [
            'default_target_path' => '/account',
        ]);

        self::assertSame($response, $handler->onAuthenticationSuccess($request, $token));
    }

    /**
     * Wires the handler the way security.yaml's `success_handler` option does.
     *
     * @param array<string, mixed> $options
     */
    protected function configuredByTheFirewall(AuthenticationSuccessHandlerInterface $default, array $options): AuthenticationSuccessHandlerInterface
    {
        $handler = new TwoFactorAwareAuthenticationSuccessHandler(
            $this->createStub(AuthenticationRequiredHandlerInterface::class),
            $default,
        );

        return new CustomAuthenticationSuccessHandler($handler, $options, 'shop');
    }

    protected function signInRequest(): Request
    {
        $request = Request::create('/login_check', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }
}
