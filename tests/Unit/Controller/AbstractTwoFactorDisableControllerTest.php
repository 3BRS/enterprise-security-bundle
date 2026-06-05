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
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorDisableController;

#[CoversClass(AbstractTwoFactorDisableController::class)]
class AbstractTwoFactorDisableControllerTest extends TestCase
{
    public function testRedirectsToLoginWhenUserNotTwoFactorCapable(): void
    {
        $controller = $this->makeController(twoFactorCapable: false);

        $response = $controller(new Request());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request());
    }

    public function testDisablesAndRedirects(): void
    {
        $controller = $this->makeController();
        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        bool $twoFactorCapable = true,
        bool $csrfValid = true,
    ): AbstractTwoFactorDisableController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $router = $this->createStub(RouterInterface::class);

        return new class($tokenStorage, $csrf, $router, $twoFactorCapable) extends AbstractTwoFactorDisableController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                protected bool $twoFactorCapable,
            ) {
                parent::__construct($tokenStorage, $csrf, $router);
            }

            protected function getCsrfTokenId(): string
            {
                return 'disable_csrf';
            }

            protected function isTwoFactorCapableUser(UserInterface $user): bool
            {
                return $this->twoFactorCapable;
            }

            protected function disableTwoFactorAndCommit(UserInterface $user): void
            {
            }

            protected function getLoginUrl(): string
            {
                return '/login';
            }

            protected function getRedirectAfterDisableUrl(): string
            {
                return '/dashboard';
            }
        };
    }
}
