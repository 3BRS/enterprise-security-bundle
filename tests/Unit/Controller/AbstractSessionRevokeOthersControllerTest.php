<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractSessionRevokeOthersController;

#[CoversClass(AbstractSessionRevokeOthersController::class)]
class AbstractSessionRevokeOthersControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request());
    }

    public function testThrowsBadRequestWithoutSession(): void
    {
        $controller = $this->makeController();

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request());
    }

    public function testRevokesOtherSessions(): void
    {
        $request = new Request();
        $storage = new MockArraySessionStorage();
        $storage->setId('current-id');
        $request->setSession(new Session($storage));

        $controller = $this->makeController();
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/sessions', $response->getTargetUrl());
    }

    protected function makeController(
        bool $enabled = true,
        bool $csrfValid = true,
    ): AbstractSessionRevokeOthersController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/sessions');

        return new class($tokenStorage, $csrf, $router, $enabled) extends AbstractSessionRevokeOthersController {
            protected function isAcceptableUser(UserInterface $user): bool
            {
                return true;
            }

            protected function revokeOtherSessions(string $currentSessionId, UserInterface $user): void
            {
            }

            protected function getSessionsListUrl(Request $request): string
            {
                return '/sessions';
            }
        };
    }
}
