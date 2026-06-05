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
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorRegenerateRecoveryCodesController;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;

#[CoversClass(AbstractTwoFactorRegenerateRecoveryCodesController::class)]
class AbstractTwoFactorRegenerateRecoveryCodesControllerTest extends TestCase
{
    public function testRedirectsToLoginWhenTwoFactorNotEnabled(): void
    {
        $controller = $this->makeController(twoFactorEnabled: false);

        $response = $controller(new Request());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testRedirectsToDashboardWhenRecoveryCodesDisabled(): void
    {
        $controller = $this->makeController(recoveryCodesEnabled: false);

        $response = $controller(new Request());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
    }

    public function testThrowsBadRequestOnInvalidCsrf(): void
    {
        $controller = $this->makeController(csrfValid: false);

        $this->expectException(BadRequestHttpException::class);
        $controller(new Request());
    }

    public function testRegeneratesAndStoresInSession(): void
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        $controller = $this->makeController();
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/recovery', $response->getTargetUrl());
        self::assertSame(['a', 'b'], $request->getSession()->get('plain_codes_key'));
    }

    public function testOverriddenGettersTakePrecedenceOverConstructorValues(): void
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        // Constructor says enabled=false (would redirect to dashboard), but the
        // subclass override flips it to true and asks for 4 codes — ensuring
        // subclasses that read settings at runtime (the plugin pattern) are
        // honoured by `__invoke` instead of being shadowed by the cached
        // constructor parameters.
        $controller = $this->makeController(
            recoveryCodesEnabled: false,
            overrideEnabled: true,
            overrideCount: 4,
        );

        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/recovery', $response->getTargetUrl());
        self::assertSame([1, 2, 3, 4], $request->getSession()->get('plain_codes_key'));
    }

    protected function makeController(
        bool $twoFactorEnabled = true,
        bool $recoveryCodesEnabled = true,
        bool $csrfValid = true,
        ?bool $overrideEnabled = null,
        ?int $overrideCount = null,
    ): AbstractTwoFactorRegenerateRecoveryCodesController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $generator = $this->createStub(RecoveryCodeGeneratorInterface::class);
        $generator->method('generate')->willReturnCallback(static fn (int $count): array => $count === 2 ? ['a', 'b'] : range(1, $count));

        $router = $this->createStub(RouterInterface::class);

        return new class($tokenStorage, $generator, $csrf, $router, $recoveryCodesEnabled, 2, $twoFactorEnabled, $overrideEnabled, $overrideCount) extends AbstractTwoFactorRegenerateRecoveryCodesController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                RecoveryCodeGeneratorInterface $generator,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $recoveryCodesEnabled,
                int $recoveryCodesCount,
                protected bool $twoFactorEnabled,
                protected ?bool $overrideEnabled,
                protected ?int $overrideCount,
            ) {
                parent::__construct($tokenStorage, $generator, $csrf, $router, $recoveryCodesEnabled, $recoveryCodesCount);
            }

            protected function isRecoveryCodesEnabled(): bool
            {
                return $this->overrideEnabled ?? parent::isRecoveryCodesEnabled();
            }

            protected function getRecoveryCodesCount(): int
            {
                return $this->overrideCount ?? parent::getRecoveryCodesCount();
            }

            protected function getCsrfTokenId(): string
            {
                return 'regen_csrf';
            }

            protected function isTwoFactorEnabledUser(UserInterface $user): bool
            {
                return $this->twoFactorEnabled;
            }

            protected function replaceRecoveryCodesAndCommit(UserInterface $user, array $plainCodes): void
            {
            }

            protected function getPlainRecoveryCodesSessionKey(): string
            {
                return 'plain_codes_key';
            }

            protected function getLoginUrl(): string
            {
                return '/login';
            }

            protected function getDashboardUrl(): string
            {
                return '/dashboard';
            }

            protected function getRecoveryCodesDisplayUrl(): string
            {
                return '/recovery';
            }
        };
    }
}
