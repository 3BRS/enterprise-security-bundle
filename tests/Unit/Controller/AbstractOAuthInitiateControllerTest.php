<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractOAuthInitiateController;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;

/** @internal test double: a provider whose callback is a cross-site form_post (like Apple) */
interface FormPostTestProviderInterface extends OAuthProviderInterface, FormPostOAuthProviderInterface
{
}

#[CoversClass(AbstractOAuthInitiateController::class)]
class AbstractOAuthInitiateControllerTest extends TestCase
{
    public function testThrowsOnUnknownProvider(): void
    {
        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(false);

        $controller = $this->makeController(registry: $registry);

        $this->expectException(OAuthProviderException::class);
        $controller(new Request(), 'unknown');
    }

    public function testThrowsWhenProviderDisabledForScope(): void
    {
        $provider = $this->createStub(OAuthProviderInterface::class);

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $controller = $this->makeController(registry: $registry, providerEnabled: false);

        $this->expectException(OAuthProviderException::class);
        $controller($this->requestWithSession(), 'google');
    }

    public function testRedirectsToProviderAuthorizationUrl(): void
    {
        $provider = $this->createStub(OAuthProviderInterface::class);
        $provider->method('getAuthorizationUrl')->willReturn('https://provider.example/auth');

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $controller = $this->makeController(registry: $registry);
        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('https://provider.example/auth', $response->getTargetUrl());
        // Normal GET-redirect providers keep using the session only — no extra cookie.
        self::assertCount(0, $response->headers->getCookies());
    }

    public function testSetsStateCookieForFormPostProvider(): void
    {
        $provider = $this->createStub(FormPostTestProviderInterface::class);
        $provider->method('getAuthorizationUrl')->willReturn('https://provider.example/auth');

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $controller = $this->makeController(registry: $registry);
        $response = $controller($this->requestWithSession(), 'apple');

        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);

        $cookie = $cookies[0];
        self::assertSame('state_key_apple', $cookie->getName());
        self::assertSame(Cookie::SAMESITE_NONE, $cookie->getSameSite());
        self::assertTrue($cookie->isSecure());
        self::assertTrue($cookie->isHttpOnly());
        self::assertStringContainsString('"state"', (string) $cookie->getValue());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        OAuthProviderRegistryInterface $registry,
        bool $providerEnabled = true,
    ): AbstractOAuthInitiateController {
        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('https://example/callback');

        return new class($registry, $router, $providerEnabled) extends AbstractOAuthInitiateController {
            public function __construct(
                OAuthProviderRegistryInterface $registry,
                RouterInterface $router,
                protected bool $providerEnabled,
            ) {
                parent::__construct($registry, $router);
            }

            protected function isProviderEnabledForScope(OAuthProviderInterface $provider): bool
            {
                return $this->providerEnabled;
            }

            protected function getOAuthGroup(): string
            {
                return 'customer';
            }

            protected function getStateSessionKey(): string
            {
                return 'state_key';
            }

            protected function getIntentSessionKey(): string
            {
                return 'intent_key';
            }

            protected function getCallbackRouteName(): string
            {
                return 'oauth_callback';
            }
        };
    }
}
