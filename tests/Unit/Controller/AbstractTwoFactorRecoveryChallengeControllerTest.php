<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorRecoveryChallengeController;
use Twig\Environment;

#[CoversClass(AbstractTwoFactorRecoveryChallengeController::class)]
class AbstractTwoFactorRecoveryChallengeControllerTest extends TestCase
{
    public function testThrowsAccessDeniedWhenNotInTwoFactorFlow(): void
    {
        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($this->createStub(TokenInterface::class));

        $controller = $this->makeController(tokenStorage: $tokenStorage);

        $this->expectException(AccessDeniedException::class);
        $controller(new Request());
    }

    public function testRendersFormOnGet(): void
    {
        $controller = $this->makeController();
        $response = $controller(new Request());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
    }

    public function testRedirectsOnSuccessfulRecovery(): void
    {
        $controller = $this->makeController(verifyReturns: true);

        $request = Request::create('/', 'POST', [
            '_recovery_code' => 'ABC-DEF-GHI',
        ]);
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
    }

    protected function makeController(
        ?TokenStorageInterface $tokenStorage = null,
        bool $verifyReturns = false,
    ): AbstractTwoFactorRecoveryChallengeController {
        if ($tokenStorage === null) {
            $innerToken = $this->createStub(TokenInterface::class);

            $twoFactorToken = $this->createStub(TwoFactorTokenInterface::class);
            $twoFactorToken->method('getUser')->willReturn($this->createStub(UserInterface::class));
            $twoFactorToken->method('getAuthenticatedToken')->willReturn($innerToken);

            $tokenStorage = $this->createStub(TokenStorageInterface::class);
            $tokenStorage->method('getToken')->willReturn($twoFactorToken);
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/dashboard');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        return new class($tokenStorage, $router, $twig, $verifyReturns) extends AbstractTwoFactorRecoveryChallengeController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                RouterInterface $router,
                Environment $twig,
                protected bool $verifyReturns,
            ) {
                parent::__construct($tokenStorage, $router, $twig);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return true;
            }

            protected function verifyAndConsumeRecoveryCode(UserInterface $user, string $code): bool
            {
                return $this->verifyReturns;
            }

            protected function getFirewallName(): string
            {
                return 'shop';
            }

            protected function getDefaultRedirectUrl(): string
            {
                return '/dashboard';
            }

            protected function getTemplate(): string
            {
                return '@Foo/recovery.html.twig';
            }
        };
    }
}
