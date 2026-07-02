<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractOAuthConfirmLinkController;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\SocialAccountLinkRecordInterface;
use Twig\Environment;

#[CoversClass(AbstractOAuthConfirmLinkController::class)]
class AbstractOAuthConfirmLinkControllerTest extends TestCase
{
    public function testRedirectsToLoginWhenNoPendingSession(): void
    {
        $controller = $this->makeController();

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testRendersFormAndPreparesChallengeOnGet(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController($recorder);

        $request = $this->requestWithSession();
        $request->getSession()->set('confirm', $this->pendingData());

        $response = $controller($request);

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
        // The challenge (e.g. emailing a code) is issued on GET...
        self::assertTrue($request->getSession()->get('prepared'));
        // ...but nothing is verified or linked yet.
        self::assertArrayNotHasKey('linkedInfo', $recorder);
    }

    public function testVerifiedChallengeOnPostLinksAndRedirects(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController($recorder);

        $request = $this->requestWithSession('POST', [
            '_code' => 'valid',
        ]);
        $request->getSession()->set('confirm', $this->pendingData());

        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);

        // The matched account is actually linked, with the pending OAuth identity.
        self::assertArrayHasKey('linkedInfo', $recorder);
        $info = $recorder['linkedInfo'];
        self::assertInstanceOf(OAuthUserInfoInterface::class, $info);
        self::assertSame('google', $info->getProvider());
        self::assertSame('pid-1', $info->getProviderUserId());
        self::assertSame('user@example.com', $info->getEmail());

        // The user is authenticated...
        self::assertTrue($request->getSession()->has('_security_shop'));
        // ...the pending session is cleared once the link has been created...
        self::assertNull($request->getSession()->get('confirm'));
        // ...and the challenge is not re-issued on POST.
        self::assertNull($request->getSession()->get('prepared'));
    }

    public function testFailedChallengeOnPostRendersErrorWithoutLinking(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController($recorder);

        $request = $this->requestWithSession('POST', [
            '_code' => 'wrong',
        ]);
        $request->getSession()->set('confirm', $this->pendingData());

        $response = $controller($request);

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
        // No link is created and the user is not authenticated on a failed challenge.
        self::assertArrayNotHasKey('linkedInfo', $recorder);
        self::assertFalse($request->getSession()->has('_security_shop'));
        // The pending session survives so the user can retry.
        self::assertNotNull($request->getSession()->get('confirm'));
    }

    public function testRedirectsToLoginWhenUserNotFound(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController($recorder);

        $request = $this->requestWithSession('POST', [
            '_code' => 'valid',
        ]);
        // The fixture resolves an empty email to no account.
        $request->getSession()->set('confirm', [
            'email' => '',
            'provider' => 'google',
            'provider_user_id' => 'pid-1',
        ]);

        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
        // No link, no authentication, and the stale pending session is cleared.
        self::assertArrayNotHasKey('linkedInfo', $recorder);
        self::assertFalse($request->getSession()->has('_security_shop'));
        self::assertNull($request->getSession()->get('confirm'));
    }

    public function testExistingLinkOwnedByAnotherAccountIsRejectedWithoutLinking(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController(
            $recorder,
            $this->createStub(SocialAccountLinkRecordInterface::class),
            linkOwnedByUser: false,
        );

        $request = $this->requestWithSession('POST', [
            '_code' => 'valid',
        ]);
        $request->getSession()->set('confirm', $this->pendingData());

        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
        // The identity already belongs to someone else: rejected with a flash, no link, no auth.
        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains(
            'three_brs.ui.social_login.already_linked_other_account',
            $session->getFlashBag()->peek('error'),
        );
        self::assertArrayNotHasKey('linkedInfo', $recorder);
        self::assertFalse($session->has('_security_shop'));
        self::assertNull($session->get('confirm'));
    }

    public function testExistingLinkOwnedBySameUserAuthenticatesWithoutRelinking(): void
    {
        $recorder = new \ArrayObject();
        $controller = $this->makeController(
            $recorder,
            $this->createStub(SocialAccountLinkRecordInterface::class),
            linkOwnedByUser: true,
        );

        $request = $this->requestWithSession('POST', [
            '_code' => 'valid',
        ]);
        $request->getSession()->set('confirm', $this->pendingData());

        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        // Already linked to this account: authenticate without creating a duplicate link.
        self::assertArrayNotHasKey('linkedInfo', $recorder);
        self::assertTrue($request->getSession()->has('_security_shop'));
        self::assertNull($request->getSession()->get('confirm'));
    }

    /**
     * @return array{email: string, provider: string, provider_user_id: string}
     */
    protected function pendingData(): array
    {
        return [
            'email' => 'user@example.com',
            'provider' => 'google',
            'provider_user_id' => 'pid-1',
        ];
    }

    /**
     * @param array<string, string> $parameters
     */
    protected function requestWithSession(string $method = 'GET', array $parameters = []): Request
    {
        $request = Request::create('/confirm', $method, $parameters);
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    /**
     * @param \ArrayObject<string, mixed>|null $recorder captures the matched user / linked
     *                                                    identity so tests can assert linking
     */
    protected function makeController(
        ?\ArrayObject $recorder = null,
        ?SocialAccountLinkRecordInterface $existingLink = null,
        bool $linkOwnedByUser = false,
    ): AbstractOAuthConfirmLinkController {
        $recorder ??= new \ArrayObject();

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/login');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        return new class($this->createStub(TokenStorageInterface::class), $router, $twig, new NullLogger(), $recorder, $existingLink, $linkOwnedByUser) extends AbstractOAuthConfirmLinkController {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                RouterInterface $router,
                Environment $twig,
                LoggerInterface $logger,
                protected \ArrayObject $recorder,
                protected ?SocialAccountLinkRecordInterface $existingLink,
                protected bool $linkOwnedByUser,
            ) {
                parent::__construct($tokenStorage, $router, $twig, $logger);
            }

            protected function getConfirmPendingSessionKey(): string
            {
                return 'confirm';
            }

            protected function getFirewallName(): string
            {
                return 'shop';
            }

            protected function getLoginRoute(): string
            {
                return 'login';
            }

            protected function getDashboardUrl(): string
            {
                return '/dashboard';
            }

            protected function getTemplate(): string
            {
                return '@Foo/confirm.html.twig';
            }

            protected function getAuditChannel(): string
            {
                return 'test.confirm';
            }

            protected function getAuditUserIdKey(): string
            {
                return 'user_id';
            }

            protected function findUserByEmail(string $email): ?UserInterface
            {
                return $email !== '' ? new TestUser('u') : null;
            }

            protected function findExistingLink(string $provider, string $providerUserId): ?SocialAccountLinkRecordInterface
            {
                return $this->existingLink;
            }

            protected function isLinkOwnedByUser(SocialAccountLinkRecordInterface $existing, UserInterface $user): bool
            {
                return $this->linkOwnedByUser;
            }

            protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void
            {
                $this->recorder['linkedUser'] = $user;
                $this->recorder['linkedInfo'] = $info;
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }

            protected function prepareChallenge(UserInterface $user, array $pending, Request $request): void
            {
                $request->getSession()->set('prepared', true);
            }

            protected function verifyChallenge(UserInterface $user, array $pending, Request $request): ?string
            {
                return $request->request->get('_code') === 'valid' ? null : 'three_brs.ui.social_login.invalid_code';
            }
        };
    }
}
