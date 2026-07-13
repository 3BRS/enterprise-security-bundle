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
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
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
        $recorder = new \ArrayObject();
        $controller = $this->makeController(verifyReturns: true, recorder: $recorder);

        $request = Request::create('/', 'POST', [
            '_recovery_code' => 'ABC-DEF-GHI',
        ]);
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        self::assertSame('ABC-DEF-GHI', $recorder['verifiedCode'] ?? null);
    }

    public function testRefusesADisabledAccountWithoutConsumingARecoveryCode(): void
    {
        // The account was disabled while its owner sat on the challenge: the half-authenticated
        // token must be dropped, and the recovery code the request carries must survive unspent.
        $recorder = new \ArrayObject();

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($this->twoFactorToken());
        $tokenStorage->expects(self::once())->method('setToken')->with(null);

        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            verifyReturns: true,
            userChecker: $this->refusingUserChecker(),
            recorder: $recorder,
        );

        $request = Request::create('/', 'POST', [
            '_recovery_code' => 'ABC-DEF-GHI',
        ]);

        try {
            $controller($request);
            self::fail('Expected an AccessDeniedException for a refused account.');
        } catch (AccessDeniedException $exception) {
            self::assertSame('Account is not allowed to sign in.', $exception->getMessage());
        }

        self::assertArrayNotHasKey('verifiedCode', $recorder);
    }

    protected function refusingUserChecker(): UserCheckerInterface
    {
        $userChecker = $this->createStub(UserCheckerInterface::class);
        $userChecker->method('checkPreAuth')->willThrowException(new DisabledException());

        return $userChecker;
    }

    protected function twoFactorToken(): TwoFactorTokenInterface
    {
        $twoFactorToken = $this->createStub(TwoFactorTokenInterface::class);
        $twoFactorToken->method('getUser')->willReturn($this->createStub(UserInterface::class));
        $twoFactorToken->method('getAuthenticatedToken')->willReturn($this->createStub(TokenInterface::class));

        return $twoFactorToken;
    }

    /**
     * @param \ArrayObject<string, mixed>|null $recorder records the recovery code the controller consumed
     */
    protected function makeController(
        ?TokenStorageInterface $tokenStorage = null,
        bool $verifyReturns = false,
        ?UserCheckerInterface $userChecker = null,
        ?\ArrayObject $recorder = null,
    ): AbstractTwoFactorRecoveryChallengeController {
        $userChecker ??= $this->createStub(UserCheckerInterface::class);
        $recorder ??= new \ArrayObject();

        if ($tokenStorage === null) {
            $tokenStorage = $this->createStub(TokenStorageInterface::class);
            $tokenStorage->method('getToken')->willReturn($this->twoFactorToken());
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/dashboard');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        return new class($tokenStorage, $router, $twig, $userChecker, $verifyReturns, $recorder) extends AbstractTwoFactorRecoveryChallengeController {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                RouterInterface $router,
                Environment $twig,
                UserCheckerInterface $userChecker,
                protected bool $verifyReturns,
                protected \ArrayObject $recorder,
            ) {
                parent::__construct($tokenStorage, $router, $twig, $userChecker);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return true;
            }

            protected function verifyAndConsumeRecoveryCode(UserInterface $user, string $code): bool
            {
                $this->recorder['verifiedCode'] = $code;

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
