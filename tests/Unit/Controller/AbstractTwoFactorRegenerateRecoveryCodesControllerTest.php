<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface as TotpTwoFactorInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorRegenerateRecoveryCodesController;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuardInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;

/** @internal test double: a user with TOTP two-factor authentication */
interface RegenerateTestTotpUserInterface extends UserInterface, TotpTwoFactorInterface
{
}

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

    public function testRedirectsASignInRestoredFromARememberMeCookieToLogin(): void
    {
        $token = $this->createStub(RememberMeToken::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $controller = $this->makeController(token: $token);
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
        self::assertSame([], $request->getSession()->all());
    }

    public function testRefusesAWrongCodeWithoutReplacingTheRecoveryCodes(): void
    {
        // Fresh recovery codes would confirm switching 2FA off, so a session without the second factor
        // must not obtain them.
        $totp = $this->createStub(TotpAuthenticatorInterface::class);
        $totp->method('checkCode')->willReturn(false);

        $recorder = new \ArrayObject();
        $controller = $this->makeController(
            totpAuthenticator: $totp,
            rateLimitGuard: $this->createStub(RateLimitGuardInterface::class),
            user: $this->totpUser(),
            recorder: $recorder,
        );

        $request = $this->requestWithCode('000000');
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        self::assertCount(0, $recorder);
        self::assertFalse($request->getSession()->has('plain_codes_key'));

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertSame(['three_brs.two_factor.confirmation_code_invalid'], $session->getFlashBag()->peek('error'));
    }

    public function testRegeneratesWithTheCurrentCodeAndClearsTheCounter(): void
    {
        $user = $this->totpUser();

        $totp = $this->createMock(TotpAuthenticatorInterface::class);
        $totp->expects(self::once())->method('checkCode')->with($user, '123456')->willReturn(true);

        $guard = $this->createMock(RateLimitGuardInterface::class);
        $guard->expects(self::once())->method('consume');
        $guard->expects(self::once())->method('reset')->with('customer', 'two_factor_code', 'user-id');

        $controller = $this->makeController(totpAuthenticator: $totp, rateLimitGuard: $guard, user: $user);

        $response = $controller($this->requestWithCode('123456'));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/recovery', $response->getTargetUrl());
    }

    public function testNeedsTheRateLimitGuardTogetherWithTheTotpAuthenticator(): void
    {
        $this->expectException(\LogicException::class);
        $this->makeController(totpAuthenticator: $this->createStub(TotpAuthenticatorInterface::class));
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
        // subclasses that read settings at runtime (the consumer pattern) are
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

    protected function requestWithCode(string $code): Request
    {
        $request = Request::create('/', 'POST', [
            '_code' => $code,
        ]);
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function totpUser(): RegenerateTestTotpUserInterface
    {
        $user = $this->createStub(RegenerateTestTotpUserInterface::class);
        $user->method('isTotpAuthenticationEnabled')->willReturn(true);
        $user->method('getUserIdentifier')->willReturn('user-id');

        return $user;
    }

    /**
     * @param \ArrayObject<int, array<int, string>>|null $recorder records the codes replaceRecoveryCodesAndCommit() stores
     */
    protected function makeController(
        bool $twoFactorEnabled = true,
        bool $recoveryCodesEnabled = true,
        bool $csrfValid = true,
        ?bool $overrideEnabled = null,
        ?int $overrideCount = null,
        ?TokenInterface $token = null,
        ?TotpAuthenticatorInterface $totpAuthenticator = null,
        ?RateLimitGuardInterface $rateLimitGuard = null,
        ?UserInterface $user = null,
        ?\ArrayObject $recorder = null,
    ): AbstractTwoFactorRegenerateRecoveryCodesController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        if ($token === null) {
            $token = $this->createStub(TokenInterface::class);
            $token->method('getUser')->willReturn($user ?? $this->createStub(UserInterface::class));
        }

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $generator = $this->createStub(RecoveryCodeGeneratorInterface::class);
        $generator->method('generate')->willReturnCallback(static fn (int $count): array => $count === 2 ? ['a', 'b'] : range(1, $count));

        $router = $this->createStub(RouterInterface::class);

        return new class($tokenStorage, $generator, $csrf, $router, $recoveryCodesEnabled, 2, $totpAuthenticator, $rateLimitGuard, $twoFactorEnabled, $overrideEnabled, $overrideCount, $recorder ?? new \ArrayObject()) extends AbstractTwoFactorRegenerateRecoveryCodesController {
            /**
             * @param \ArrayObject<int, array<int, string>> $recorder
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                RecoveryCodeGeneratorInterface $generator,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                bool $recoveryCodesEnabled,
                int $recoveryCodesCount,
                ?TotpAuthenticatorInterface $totpAuthenticator,
                ?RateLimitGuardInterface $rateLimitGuard,
                protected bool $twoFactorEnabled,
                protected ?bool $overrideEnabled,
                protected ?int $overrideCount,
                protected \ArrayObject $recorder,
            ) {
                parent::__construct($tokenStorage, $generator, $csrf, $router, $recoveryCodesEnabled, $recoveryCodesCount, $totpAuthenticator, $rateLimitGuard);
            }

            protected function getRateLimitGroup(): string
            {
                return 'customer';
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
                $this->recorder[] = $plainCodes;
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
