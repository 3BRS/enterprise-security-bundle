<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractSessionRevokeController;
use ThreeBRS\EnterpriseSecurityBundle\Session\SessionRecordInterface;

#[CoversClass(AbstractSessionRevokeController::class)]
class AbstractSessionRevokeControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsAccessDeniedWhenUserNotAcceptable(): void
    {
        $controller = $this->makeController(acceptUser: false, tokenUser: $this->createStub(UserInterface::class));

        $this->expectException(AccessDeniedHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsNotFoundWhenSessionMissing(): void
    {
        $controller = $this->makeController(session: null);

        $this->expectException(NotFoundHttpException::class);
        $controller($this->requestWithSession(), 1);
    }

    public function testFlashesErrorWhenRevokingCurrentSession(): void
    {
        $session = $this->createStub(SessionRecordInterface::class);
        $session->method('getSessionId')->willReturn('current-session-id');

        $request = $this->requestWithSession('current-session-id');

        $controller = $this->makeController(session: $session);
        $response = $controller($request, 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
    }

    public function testRevokesNonCurrentSession(): void
    {
        $session = $this->createStub(SessionRecordInterface::class);
        $session->method('getSessionId')->willReturn('other-session-id');

        $request = $this->requestWithSession('current-session-id');

        $controller = $this->makeController(session: $session);
        $response = $controller($request, 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/sessions', $response->getTargetUrl());
    }

    protected function requestWithSession(string $sessionId = ''): Request
    {
        $storage = new MockArraySessionStorage();
        $storage->setId($sessionId);
        $request = new Request();
        $request->setSession(new Session($storage));

        return $request;
    }

    protected function makeController(
        bool $enabled = true,
        bool $csrfValid = true,
        bool $acceptUser = true,
        ?UserInterface $tokenUser = null,
        ?SessionRecordInterface $session = null,
    ): AbstractSessionRevokeController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        if ($tokenUser !== null || $acceptUser) {
            $token = $this->createStub(TokenInterface::class);
            $token->method('getUser')->willReturn($tokenUser ?? $this->createStub(UserInterface::class));
            $tokenStorage->method('getToken')->willReturn($token);
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/sessions');

        return new class($tokenStorage, $csrf, $router, $enabled, $acceptUser, $session) extends AbstractSessionRevokeController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $enabled,
                protected bool $acceptUser,
                protected ?SessionRecordInterface $session,
            ) {
                parent::__construct($tokenStorage, $csrf, $router, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function findSessionForUser(int $id, UserInterface $user): ?SessionRecordInterface
            {
                return $this->session;
            }

            protected function revokeSession(SessionRecordInterface $session): void
            {
            }

            protected function getSessionsListUrl(Request $request): string
            {
                return '/sessions';
            }
        };
    }
}
