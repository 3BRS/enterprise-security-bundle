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
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractSocialAccountUnlinkController;

#[CoversClass(AbstractSocialAccountUnlinkController::class)]
class AbstractSocialAccountUnlinkControllerTest extends TestCase
{
    public function testThrowsAccessDeniedForBadUser(): void
    {
        $controller = $this->makeController(acceptUser: false);

        $this->expectException(AccessDeniedException::class);
        $controller(new Request(), 'google');
    }

    public function testThrowsAccessDeniedOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(AccessDeniedException::class);
        $controller(new Request(), 'google');
    }

    public function testRedirectsWithErrorWhenLastMethod(): void
    {
        $controller = $this->makeController(canUnlink: false);

        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
    }

    public function testRedirectsAfterUnlink(): void
    {
        $controller = $this->makeController(canUnlink: true, deleted: true);

        $response = $controller($this->requestWithSession(), 'google');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/social', $response->getTargetUrl());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        bool $acceptUser = true,
        bool $csrfValid = true,
        bool $canUnlink = true,
        bool $deleted = true,
    ): AbstractSocialAccountUnlinkController {
        $security = $this->createStub(Security::class);
        $security->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/social');

        return new class($security, $csrf, $router, new NullLogger(), $acceptUser, $canUnlink, $deleted) extends AbstractSocialAccountUnlinkController {
            public function __construct(
                Security $security,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                NullLogger $logger,
                protected bool $acceptUser,
                protected bool $canUnlink,
                protected bool $deleted,
            ) {
                parent::__construct($security, $csrf, $router, $logger);
            }

            protected function getCsrfTokenId(string $provider): string
            {
                return 'unlink_csrf_' . $provider;
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function canUnlinkProvider(UserInterface $user, string $provider): bool
            {
                return $this->canUnlink;
            }

            protected function deleteLinkForProvider(UserInterface $user, string $provider): bool
            {
                return $this->deleted;
            }

            protected function getSocialAccountsUrl(): string
            {
                return '/social';
            }

            protected function getAuditChannel(): string
            {
                return 'test.social';
            }

            protected function getAuditUserIdKey(): string
            {
                return 'user_id';
            }
        };
    }
}
