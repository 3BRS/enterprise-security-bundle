<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
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

    public function testRendersFormOnGetWithPendingData(): void
    {
        $controller = $this->makeController();

        $request = $this->requestWithSession();
        $request->getSession()->set('confirm', [
            'email' => 'user@example.com',
            'provider' => 'google',
            'provider_user_id' => 'pid-1',
        ]);

        $response = $controller($request);

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(): AbstractOAuthConfirmLinkController
    {
        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/login');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        return new class($this->createStub(UserPasswordHasherInterface::class), $this->createStub(TokenStorageInterface::class), $router, $twig, new NullLogger()) extends AbstractOAuthConfirmLinkController {
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
                return null;
            }

            protected function isLinkOwnedByUser(SocialAccountLinkRecordInterface $existing, UserInterface $user): bool
            {
                return false;
            }

            protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void
            {
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }
        };
    }
}
