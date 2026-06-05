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
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractUnlockUserController;

#[CoversClass(AbstractUnlockUserController::class)]
class AbstractUnlockUserControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(false);

        $controller = $this->makeController(csrf: $csrf, enabled: true);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request(), 1);
    }

    public function testThrowsNotFoundWhenUserMissing(): void
    {
        $controller = $this->makeController(csrf: $this->validCsrfStub(), enabled: true, unlockReturns: null);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 1);
    }

    public function testRedirectsAndFlashesInfoWhenAlreadyUnlocked(): void
    {
        $controller = $this->makeController(
            csrf: $this->validCsrfStub(),
            enabled: true,
            unlockReturns: false,
        );

        $response = $controller($this->requestWithSession(), 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/admin/locked', $response->getTargetUrl());
    }

    public function testRedirectsAndFlashesSuccessWhenUnlocked(): void
    {
        $controller = $this->makeController(
            csrf: $this->validCsrfStub(),
            enabled: true,
            unlockReturns: true,
        );

        $response = $controller($this->requestWithSession(), 1);

        self::assertInstanceOf(RedirectResponse::class, $response);
    }

    protected function validCsrfStub(): CsrfTokenManagerInterface
    {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);

        return $csrf;
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        ?CsrfTokenManagerInterface $csrf = null,
        bool $enabled = true,
        ?bool $unlockReturns = true,
    ): AbstractUnlockUserController {
        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/admin/locked');

        return new class($csrf ?? $this->createStub(CsrfTokenManagerInterface::class), $router, $enabled, $unlockReturns) extends AbstractUnlockUserController {
            public function __construct(
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $enabled,
                protected ?bool $unlockReturns,
            ) {
                parent::__construct($csrf, $router, $enabled);
            }

            protected function getCsrfTokenId(): string
            {
                return 'unlock_csrf';
            }

            protected function getLockedListUrl(): string
            {
                return '/admin/locked';
            }

            protected function attemptUnlock(int $id): ?bool
            {
                return $this->unlockReturns;
            }
        };
    }
}
