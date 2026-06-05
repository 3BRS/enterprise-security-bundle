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
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyDeleteController;

#[CoversClass(AbstractPasskeyDeleteController::class)]
class AbstractPasskeyDeleteControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsAccessDeniedForBadUser(): void
    {
        $controller = $this->makeController(acceptUser: false);

        $this->expectException(AccessDeniedHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsNotFoundOnMissingCredential(): void
    {
        $controller = $this->makeController(credential: null);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 1);
    }

    public function testRedirectsWithErrorWhenLastAuthMethod(): void
    {
        $controller = $this->makeController(credential: new \stdClass(), canRemove: false);

        $response = $controller($this->requestWithSession(), 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
    }

    public function testDeletesAndRedirects(): void
    {
        $controller = $this->makeController(credential: new \stdClass(), canRemove: true);

        $response = $controller($this->requestWithSession(), 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/passkeys', $response->getTargetUrl());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
        bool $csrfValid = true,
        ?object $credential = null,
        bool $canRemove = true,
    ): AbstractPasskeyDeleteController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/passkeys');

        return new class($tokenStorage, $csrf, $router, $enabled, $acceptUser, $credential, $canRemove) extends AbstractPasskeyDeleteController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $enabled,
                protected bool $acceptUser,
                protected ?object $credential,
                protected bool $canRemove,
            ) {
                parent::__construct($tokenStorage, $csrf, $router, $enabled);
            }

            protected function getCsrfTokenId(): string
            {
                return 'delete_csrf';
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function findCredentialForUser(int $id, UserInterface $user): ?object
            {
                return $this->credential;
            }

            protected function canRemoveCredential(UserInterface $user): bool
            {
                return $this->canRemove;
            }

            protected function deleteCredential(object $credential): void
            {
            }

            protected function getPasskeyListUrl(): string
            {
                return '/passkeys';
            }
        };
    }
}
