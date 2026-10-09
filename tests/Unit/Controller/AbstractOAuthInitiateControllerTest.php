<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractOAuthInitiateController;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSigner;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSignerInterface;

/** @internal test double: a provider whose callback is a cross-site form_post (like Apple) */
interface FormPostTestProviderInterface extends OAuthProviderInterface, FormPostOAuthProviderInterface
{
}

#[CoversClass(AbstractOAuthInitiateController::class)]
class AbstractOAuthInitiateControllerTest extends TestCase
{
    protected const SECRET = 'test-secret';

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
        // The value is HMAC-signed, not plain JSON — it must decode back to the state payload.
        $value = (string) $cookie->getValue();
        self::assertStringNotContainsString('"state"', $value);
        $decoded = ($this->signer())->decode($value);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('state', $decoded);
        self::assertSame('login', $decoded['intent']);
    }

    public function testRefusesALinkWithoutAFullSignIn(): void
    {
        // A sign-in that waits for its two-factor code is not a full one; the firewall turns the refusal
        // into the code page or the sign-in page.
        $user = new TestUser('victim');
        $security = $this->createStub(Security::class);
        $security->method('getToken')->willReturn(
            new TwoFactorToken(new UsernamePasswordToken($user, 'main', $user->getRoles()), null, 'main', ['totp']),
        );
        $security->method('getUser')->willReturn($user);

        $controller = $this->makeController(registry: $this->registryFor($this->createStub(FormPostTestProviderInterface::class)), security: $security);

        $request = $this->requestWithSession();
        $request->query->set('intent', 'link');

        try {
            $controller($request, 'apple');
            self::fail('The link was started without a full sign-in.');
        } catch (AccessDeniedException) {
        }

        self::assertSame([], $request->getSession()->all());
    }

    public function testRefusesALinkWithoutTheSecurityService(): void
    {
        $controller = $this->makeController(registry: $this->registryFor($this->createStub(OAuthProviderInterface::class)));

        $request = $this->requestWithSession();
        $request->query->set('intent', 'link');

        $this->expectException(AccessDeniedException::class);
        $controller($request, 'google');
    }

    public function testStartsALinkForAFullySignedInUser(): void
    {
        $provider = $this->createStub(OAuthProviderInterface::class);
        $provider->method('getAuthorizationUrl')->willReturn('https://provider.example/auth');

        $controller = $this->makeController(registry: $this->registryFor($provider), security: $this->securityFor(new TestUser('linker')));

        $request = $this->requestWithSession();
        $request->query->set('intent', 'link');
        $response = $controller($request, 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('https://provider.example/auth', $response->getTargetUrl());
        self::assertSame('link', $request->getSession()->get('intent_key'));
    }

    public function testFormPostLinkCarriesTheFullySignedInUserInTheStateCookie(): void
    {
        $provider = $this->createStub(FormPostTestProviderInterface::class);
        $provider->method('getAuthorizationUrl')->willReturn('https://provider.example/auth');

        $controller = $this->makeController(registry: $this->registryFor($provider), security: $this->securityFor(new TestUser('linker')));

        $request = $this->requestWithSession();
        $request->query->set('intent', 'link');
        $response = $controller($request, 'apple');

        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        $decoded = ($this->signer())->decode((string) $cookies[0]->getValue());
        self::assertIsArray($decoded);
        self::assertSame('link', $decoded['intent']);
        self::assertSame('linker', $decoded['user']);
    }

    protected function registryFor(OAuthProviderInterface $provider): OAuthProviderRegistryInterface
    {
        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        return $registry;
    }

    protected function securityFor(TestUser $user): Security
    {
        $security = $this->createStub(Security::class);
        $security->method('getToken')->willReturn(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        $security->method('getUser')->willReturn($user);

        return $security;
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    /**
     * Fixed clock so the signed value's expiry is deterministic — the signer stamps `exp` from it.
     */
    protected function signer(): StateCookieSigner
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable('@1700000000'));

        return new StateCookieSigner(self::SECRET, $clock);
    }

    protected function makeController(
        OAuthProviderRegistryInterface $registry,
        bool $providerEnabled = true,
        ?Security $security = null,
    ): AbstractOAuthInitiateController {
        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('https://example/callback');

        return new class($registry, $router, $this->signer(), $providerEnabled, $security) extends AbstractOAuthInitiateController {
            public function __construct(
                OAuthProviderRegistryInterface $registry,
                RouterInterface $router,
                StateCookieSignerInterface $stateCookieSigner,
                protected bool $providerEnabled,
                ?Security $security,
            ) {
                parent::__construct($registry, $router, $stateCookieSigner, $security);
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
