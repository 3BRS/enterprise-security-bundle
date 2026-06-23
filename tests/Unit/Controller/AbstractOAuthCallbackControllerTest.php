<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractOAuthCallbackController;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfo;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;

/** @internal test double: a provider whose callback is a cross-site form_post (like Apple) */
interface FormPostCallbackTestProviderInterface extends OAuthProviderInterface, FormPostOAuthProviderInterface
{
}

#[CoversClass(AbstractOAuthCallbackController::class)]
class AbstractOAuthCallbackControllerTest extends TestCase
{
    public function testThrowsOnUnknownProvider(): void
    {
        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(false);

        $controller = $this->makeController(registry: $registry);

        $this->expectException(OAuthProviderException::class);
        $controller(new Request(), 'unknown');
    }

    public function testLoginRedirectsExistingUserToDashboard(): void
    {
        $existing = $this->stubUser();
        $controller = $this->makeController(existingUser: $existing);

        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
    }

    public function testRedirectsToLoginOnFetchFailure(): void
    {
        $provider = $this->createStub(OAuthProviderInterface::class);
        $provider->method('fetchUserInfo')->willThrowException(new OAuthProviderException('boom'));

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $controller = $this->makeController(registry: $registry);
        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testReadsStateFromCookieAndClearsItForFormPostProvider(): void
    {
        // The expected state must come from the dedicated cookie (not the session), and be
        // dropped from the response afterwards (single-use).
        $provider = $this->createMock(FormPostCallbackTestProviderInterface::class);
        $provider->expects(self::once())
            ->method('fetchUserInfo')
            ->with(self::anything(), self::anything(), 'cookie-state', 'customer')
            ->willReturn(new OAuthUserInfo('apple', 'pid-1', 'user@example.com'));

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $controller = $this->makeController(registry: $registry, existingUser: $this->stubUser());

        $request = $this->requestWithSession();
        $request->cookies->set('state_apple', (string) json_encode([
            'state' => 'cookie-state',
            'intent' => 'login',
        ]));

        $response = $controller($request, 'apple');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());

        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        self::assertSame('state_apple', $cookies[0]->getName());
        self::assertLessThan(time(), $cookies[0]->getExpiresTime());
    }

    public function testFormPostLinkReauthenticatesTheCookieResolvedUser(): void
    {
        // A link started while logged in returns on the cross-site POST without the session,
        // so the user is resolved from the cookie and must be re-authenticated — otherwise the
        // fresh session cookie set on the response would silently log them out.
        $provider = $this->createStub(FormPostCallbackTestProviderInterface::class);
        $provider->method('fetchUserInfo')->willReturn(new OAuthUserInfo('apple', 'pid-1', 'user@example.com'));

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::once())->method('setToken');

        $controller = $this->makeController(
            registry: $registry,
            identifierUser: new TestUser('linker'),
            tokenStorage: $tokenStorage,
        );

        $request = $this->requestWithSession();
        $request->cookies->set('state_apple', (string) json_encode([
            'state' => 'cookie-state',
            'intent' => 'link',
            'user' => 'linker',
        ]));

        $response = $controller($request, 'apple');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/social-accounts', $response->getTargetUrl());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function stubUser(): UserInterface
    {
        return new TestUser('user-id');
    }

    protected function makeController(
        ?OAuthProviderRegistryInterface $registry = null,
        ?UserInterface $existingUser = null,
        ?UserInterface $identifierUser = null,
        ?TokenStorageInterface $tokenStorage = null,
    ): AbstractOAuthCallbackController {
        if ($registry === null) {
            $provider = $this->createStub(OAuthProviderInterface::class);
            $provider->method('fetchUserInfo')->willReturn(new OAuthUserInfo('google', 'pid-1', 'user@example.com'));

            $registry = $this->createStub(OAuthProviderRegistryInterface::class);
            $registry->method('has')->willReturn(true);
            $registry->method('get')->willReturn($provider);
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturnCallback(static fn (string $name) => '/' . str_replace('_', '-', $name));

        return new class($registry, $router, $tokenStorage ?? $this->createStub(TokenStorageInterface::class), $this->createStub(Security::class), new NullLogger(), $existingUser, $identifierUser) extends AbstractOAuthCallbackController {
            public function __construct(
                OAuthProviderRegistryInterface $registry,
                RouterInterface $router,
                TokenStorageInterface $tokenStorage,
                Security $security,
                NullLogger $logger,
                protected ?UserInterface $existingUser,
                protected ?UserInterface $identifierUser,
            ) {
                parent::__construct($registry, $router, $tokenStorage, $security, $logger);
            }

            protected function getOAuthGroup(): string
            {
                return 'customer';
            }

            protected function getCallbackRouteName(): string
            {
                return 'oauth_callback';
            }

            protected function getFirewallName(): string
            {
                return 'shop';
            }

            protected function getStateSessionKey(): string
            {
                return 'state';
            }

            protected function getIntentSessionKey(): string
            {
                return 'intent';
            }

            protected function getConfirmPendingSessionKey(): string
            {
                return 'confirm';
            }

            protected function getLoginRoute(): string
            {
                return 'login';
            }

            protected function getDashboardUrl(): string
            {
                return '/dashboard';
            }

            protected function getSocialAccountsRoute(): string
            {
                return 'social-accounts';
            }

            protected function getConfirmLinkRoute(): string
            {
                return 'confirm-link';
            }

            protected function getAuditChannel(): string
            {
                return 'test.oauth';
            }

            protected function getAuditUserIdKey(): string
            {
                return 'user_id';
            }

            protected function isAcceptableCurrentUser(?UserInterface $user): bool
            {
                return $user !== null;
            }

            protected function findExistingLinkUser(OAuthUserInfoInterface $info): ?UserInterface
            {
                return $this->existingUser;
            }

            protected function findUserByEmail(string $email): ?UserInterface
            {
                return null;
            }

            protected function findUserByIdentifier(string $identifier): ?UserInterface
            {
                return $this->identifierUser;
            }

            protected function canAutoRegister(OAuthUserInfoInterface $info): bool
            {
                return false;
            }

            protected function registerAndLink(OAuthUserInfoInterface $info): UserInterface
            {
                throw new \LogicException('not reached');
            }

            protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void
            {
            }

            protected function touchLastUsed(UserInterface $user, OAuthUserInfoInterface $info): void
            {
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }
        };
    }
}
