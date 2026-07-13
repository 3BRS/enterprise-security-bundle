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
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractOAuthCallbackController;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfo;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSigner;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSignerInterface;

/** @internal test double: a provider whose callback is a cross-site form_post (like Apple) */
interface FormPostCallbackTestProviderInterface extends OAuthProviderInterface, FormPostOAuthProviderInterface
{
}

#[CoversClass(AbstractOAuthCallbackController::class)]
class AbstractOAuthCallbackControllerTest extends TestCase
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
        $request->cookies->set('state_apple', (new StateCookieSigner(self::SECRET))->encode([
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
        $request->cookies->set('state_apple', (new StateCookieSigner(self::SECRET))->encode([
            'state' => 'cookie-state',
            'intent' => 'link',
            'user' => 'linker',
        ]));

        $response = $controller($request, 'apple');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/social-accounts', $response->getTargetUrl());
    }

    public function testFormPostLinkIgnoresAForgedUnsignedStateCookie(): void
    {
        // Security regression: an attacker crafts the callback (curl) with an UNSIGNED cookie
        // naming a victim as the link user. Without a valid HMAC the cookie is rejected, so no
        // user is resolved, nothing is authenticated, and the attacker is not signed in as the
        // victim.
        $provider = $this->createStub(FormPostCallbackTestProviderInterface::class);
        $provider->method('fetchUserInfo')->willReturn(new OAuthUserInfo('apple', 'pid-1', 'user@example.com'));

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            registry: $registry,
            identifierUser: new TestUser('victim'),
            tokenStorage: $tokenStorage,
        );

        $request = $this->requestWithSession();
        // Forged: plain JSON, no HMAC signature — what curl can set freely.
        $request->cookies->set('state_apple', (string) json_encode([
            'state' => 'cookie-state',
            'intent' => 'link',
            'user' => 'victim',
        ]));

        $response = $controller($request, 'apple');

        // Rejected cookie -> intent falls back to 'login', no link user -> no auth -> /login.
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testRefusesADisabledAccountOnTheSessionlessLinkPathWithoutAuthenticatingOrLinking(): void
    {
        // The cross-site form_post link resolves the user from the signed state cookie rather than
        // from a live session, so the account can well have been disabled (or its self-service
        // deletion requested) between initiate and callback. Such an account must neither be
        // signed back in nor handed a new way in.
        $provider = $this->createStub(FormPostCallbackTestProviderInterface::class);
        $provider->method('fetchUserInfo')->willReturn(new OAuthUserInfo('apple', 'pid-1', 'user@example.com'));

        $registry = $this->createStub(OAuthProviderRegistryInterface::class);
        $registry->method('has')->willReturn(true);
        $registry->method('get')->willReturn($provider);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $recorder = new \ArrayObject();

        $controller = $this->makeController(
            registry: $registry,
            identifierUser: new TestUser('linker'),
            tokenStorage: $tokenStorage,
            userChecker: $this->refusingUserChecker(),
            recorder: $recorder,
        );

        $request = $this->requestWithSession();
        $request->cookies->set('state_apple', (new StateCookieSigner(self::SECRET))->encode([
            'state' => 'cookie-state',
            'intent' => 'link',
            'user' => 'linker',
        ]));

        $response = $controller($request, 'apple');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());

        // No token is written and no social account is linked.
        self::assertArrayNotHasKey('linkedUser', $recorder);

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains('three_brs.account_state.sign_in_refused', $session->getFlashBag()->peek('error'));
    }

    public function testRefusesADisabledLinkedAccountWithoutSigningItIn(): void
    {
        $recorder = new \ArrayObject();

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            existingUser: $this->stubUser(),
            tokenStorage: $tokenStorage,
            userChecker: $this->refusingUserChecker(),
            recorder: $recorder,
        );

        $request = $this->requestWithSession();
        $response = $controller($request, 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());

        // Nothing is mutated: the link is not touched and no token is written.
        self::assertArrayNotHasKey('touchedLastUsed', $recorder);

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains('three_brs.account_state.sign_in_refused', $session->getFlashBag()->peek('error'));
    }

    public function testRefusesADisabledAccountMatchedByEmailWithoutStartingTheConfirmLink(): void
    {
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            userChecker: $this->refusingUserChecker(),
            emailUser: new TestUser('by-email'),
        );

        $request = $this->requestWithSession();
        $response = $controller($request, 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());

        // No point emailing a confirm-link code for an account that cannot sign in anyway.
        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertNull($session->get('confirm'));
        self::assertContains('three_brs.account_state.sign_in_refused', $session->getFlashBag()->peek('error'));
    }

    public function testAutoRegistersAnUnknownIdentityAndSignsItIn(): void
    {
        $newUser = new TestUser('freshly-registered');

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::once())->method('setToken');

        $recorder = new \ArrayObject();
        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            recorder: $recorder,
            registeredUser: $newUser,
        );

        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        self::assertSame($newUser, $recorder['registeredUser'] ?? null);
    }

    public function testRefusesAFreshlyRegisteredAccountThatCannotSignIn(): void
    {
        // Nothing in the contract of registerAndLink() promises a usable account, so the guard holds
        // for this branch too rather than trusting the subclass.
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            userChecker: $this->refusingUserChecker(),
            registeredUser: new TestUser('freshly-registered'),
        );

        $request = $this->requestWithSession();
        $response = $controller($request, 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains('three_brs.account_state.sign_in_refused', $session->getFlashBag()->peek('error'));
    }

    protected function refusingUserChecker(): UserCheckerInterface
    {
        $userChecker = $this->createStub(UserCheckerInterface::class);
        $userChecker->method('checkPreAuth')->willThrowException(new DisabledException());

        return $userChecker;
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

    /**
     * @param \ArrayObject<string, mixed>|null $recorder records the mutating hooks the controller calls
     */
    protected function makeController(
        ?OAuthProviderRegistryInterface $registry = null,
        ?UserInterface $existingUser = null,
        ?UserInterface $identifierUser = null,
        ?TokenStorageInterface $tokenStorage = null,
        ?UserCheckerInterface $userChecker = null,
        ?UserInterface $emailUser = null,
        ?\ArrayObject $recorder = null,
        ?UserInterface $registeredUser = null,
    ): AbstractOAuthCallbackController {
        $userChecker ??= $this->createStub(UserCheckerInterface::class);
        $recorder ??= new \ArrayObject();

        if ($registry === null) {
            $provider = $this->createStub(OAuthProviderInterface::class);
            $provider->method('fetchUserInfo')->willReturn(new OAuthUserInfo('google', 'pid-1', 'user@example.com'));

            $registry = $this->createStub(OAuthProviderRegistryInterface::class);
            $registry->method('has')->willReturn(true);
            $registry->method('get')->willReturn($provider);
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturnCallback(static fn (string $name) => '/' . str_replace('_', '-', $name));

        return new class($registry, $router, $tokenStorage ?? $this->createStub(TokenStorageInterface::class), $this->createStub(Security::class), new NullLogger(), new StateCookieSigner(self::SECRET), $userChecker, $existingUser, $identifierUser, $emailUser, $recorder, $registeredUser) extends AbstractOAuthCallbackController {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                OAuthProviderRegistryInterface $registry,
                RouterInterface $router,
                TokenStorageInterface $tokenStorage,
                Security $security,
                NullLogger $logger,
                StateCookieSignerInterface $stateCookieSigner,
                UserCheckerInterface $userChecker,
                protected ?UserInterface $existingUser,
                protected ?UserInterface $identifierUser,
                protected ?UserInterface $emailUser,
                protected \ArrayObject $recorder,
                protected ?UserInterface $registeredUser,
            ) {
                parent::__construct($registry, $router, $tokenStorage, $security, $logger, $stateCookieSigner, $userChecker);
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
                return $this->emailUser;
            }

            protected function findUserByIdentifier(string $identifier): ?UserInterface
            {
                return $this->identifierUser;
            }

            protected function canAutoRegister(OAuthUserInfoInterface $info): bool
            {
                return $this->registeredUser !== null;
            }

            protected function registerAndLink(OAuthUserInfoInterface $info): UserInterface
            {
                if ($this->registeredUser === null) {
                    throw new \LogicException('not reached');
                }

                $this->recorder['registeredUser'] = $this->registeredUser;

                return $this->registeredUser;
            }

            protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void
            {
                $this->recorder['linkedUser'] = $user;
            }

            protected function touchLastUsed(UserInterface $user, OAuthUserInfoInterface $info): void
            {
                $this->recorder['touchedLastUsed'] = $user;
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }
        };
    }
}
