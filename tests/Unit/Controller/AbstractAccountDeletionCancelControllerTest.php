<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractAccountDeletionCancelController;

#[CoversClass(AbstractAccountDeletionCancelController::class)]
class AbstractAccountDeletionCancelControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(
            csrf: $this->createStub(CsrfTokenManagerInterface::class),
            router: $this->createStub(RouterInterface::class),
            enabled: false,
        );

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 42);
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(false);

        $controller = $this->makeController(
            csrf: $csrf,
            router: $this->createStub(RouterInterface::class),
            enabled: true,
        );

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request(), 42);
    }

    public function testThrowsNotFoundWhenRequestDoesNotExist(): void
    {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);

        $controller = $this->makeController(
            csrf: $csrf,
            router: $this->createStub(RouterInterface::class),
            enabled: true,
            cancelReturns: false,
        );

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request(), 42);
    }

    public function testRedirectsToListOnSuccess(): void
    {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/admin/deletions');

        $request = new Request();
        $request->setSession(new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage()));

        $controller = $this->makeController(
            csrf: $csrf,
            router: $router,
            enabled: true,
            cancelReturns: true,
        );

        $response = $controller($request, 42);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/admin/deletions', $response->getTargetUrl());
    }

    protected function makeController(
        CsrfTokenManagerInterface $csrf,
        RouterInterface $router,
        bool $enabled,
        bool $cancelReturns = true,
    ): AbstractAccountDeletionCancelController {
        return new class($csrf, $router, $enabled, $cancelReturns) extends AbstractAccountDeletionCancelController {
            public function __construct(
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $enabled,
                protected bool $cancelReturns,
            ) {
                parent::__construct($csrf, $router, $enabled);
            }

            protected function cancelDeletionRequest(int $id): bool
            {
                return $this->cancelReturns;
            }

            protected function getDeletionsListUrl(): string
            {
                return '/admin/deletions';
            }
        };
    }
}
