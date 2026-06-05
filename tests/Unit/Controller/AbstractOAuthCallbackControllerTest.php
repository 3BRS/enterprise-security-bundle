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
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfo;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;

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

        return new class($registry, $router, $this->createStub(TokenStorageInterface::class), $this->createStub(Security::class), new NullLogger(), $existingUser) extends AbstractOAuthCallbackController {
            public function __construct(
                OAuthProviderRegistryInterface $registry,
                RouterInterface $router,
                TokenStorageInterface $tokenStorage,
                Security $security,
                NullLogger $logger,
                protected ?UserInterface $existingUser,
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
