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
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Fixture\Recorder;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorDisableController;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuardInterface;

/** @internal test double: a user with TOTP two-factor authentication */
interface DisableTestTotpUserInterface extends UserInterface, TotpTwoFactorInterface
{
}

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

    public function testRedirectsASignInRestoredFromARememberMeCookieToLogin(): void
    {
        $token = $this->createStub(RememberMeToken::class);
        $token->method('getUser')->willReturn($this->totpUser());

        $recorder = new Recorder();
        $controller = $this->makeController(token: $token, recorder: $recorder);

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
        self::assertCount(0, $recorder);
    }

    public function testNeedsTheRateLimitGuardTogetherWithTheTotpAuthenticator(): void
    {
        $this->expectException(\LogicException::class);
        $this->makeController(totpAuthenticator: $this->createStub(TotpAuthenticatorInterface::class), withoutGuard: true);
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

    public function testDisablesWithTheCurrentTotpCode(): void
    {
        $user = $this->totpUser();

        $totp = $this->createMock(TotpAuthenticatorInterface::class);
        $totp->expects(self::once())->method('checkCode')->with($user, '123456')->willReturn(true);

        $recorder = new Recorder();
        $controller = $this->makeController(user: $user, totpAuthenticator: $totp, recorder: $recorder);

        $response = $controller($this->requestWithSession(' 123456 '));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        self::assertSame($user, $recorder['disabledUser'] ?? null);
    }

    public function testDisablesWithARecoveryCode(): void
    {
        $totp = $this->createStub(TotpAuthenticatorInterface::class);
        $totp->method('checkCode')->willReturn(false);

        $recorder = new Recorder();
        $controller = $this->makeController(
            user: $this->totpUser(),
            totpAuthenticator: $totp,
            recorder: $recorder,
            validRecoveryCode: 'ABCD-1234',
        );

        $controller($this->requestWithSession('ABCD-1234'));

        self::assertArrayHasKey('disabledUser', $recorder);
    }

    public function testRefusesAWrongCode(): void
    {
        $totp = $this->createStub(TotpAuthenticatorInterface::class);
        $totp->method('checkCode')->willReturn(false);

        $recorder = new Recorder();
        $controller = $this->makeController(user: $this->totpUser(), totpAuthenticator: $totp, recorder: $recorder);

        $request = $this->requestWithSession('000000');
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/two-factor', $response->getTargetUrl());
        self::assertArrayNotHasKey('disabledUser', $recorder);
        self::assertSame(['three_brs.two_factor.confirmation_code_invalid'], $this->flashes($request, 'error'));
    }

    public function testRefusesAMissingCodeWithoutCheckingOrCountingIt(): void
    {
        $totp = $this->createMock(TotpAuthenticatorInterface::class);
        $totp->expects(self::never())->method('checkCode');

        $guard = $this->createMock(RateLimitGuardInterface::class);
        $guard->expects(self::never())->method('consume');

        $recorder = new Recorder();
        $controller = $this->makeController(user: $this->totpUser(), totpAuthenticator: $totp, rateLimitGuard: $guard, recorder: $recorder);

        $controller($this->requestWithSession());

        self::assertArrayNotHasKey('disabledUser', $recorder);
    }

    public function testRefusesACodeForAUserWithoutTotpEnabled(): void
    {
        // scheb's TotpAuthenticator throws for a user without a TOTP secret.
        $user = $this->createStub(DisableTestTotpUserInterface::class);
        $user->method('isTotpAuthenticationEnabled')->willReturn(false);

        $totp = $this->createMock(TotpAuthenticatorInterface::class);
        $totp->expects(self::never())->method('checkCode');

        $recorder = new Recorder();
        $controller = $this->makeController(user: $user, totpAuthenticator: $totp, recorder: $recorder);

        $controller($this->requestWithSession('123456'));

        self::assertArrayNotHasKey('disabledUser', $recorder);
    }

    public function testCountsEveryCodeAttemptForTheUser(): void
    {
        $request = $this->requestWithSession('000000');

        $guard = $this->createMock(RateLimitGuardInterface::class);
        $guard->expects(self::once())->method('consume')->with($request, 'customer', 'two_factor_code', 'user-id');
        $guard->expects(self::never())->method('reset');

        $totp = $this->createStub(TotpAuthenticatorInterface::class);
        $totp->method('checkCode')->willReturn(false);

        $controller = $this->makeController(user: $this->totpUser(), totpAuthenticator: $totp, rateLimitGuard: $guard);

        $controller($request);
    }

    public function testClearsTheCounterOnceTwoFactorIsSwitchedOff(): void
    {
        $guard = $this->createMock(RateLimitGuardInterface::class);
        $guard->expects(self::once())->method('consume');
        $guard->expects(self::once())->method('reset')->with('customer', 'two_factor_code', 'user-id');

        $totp = $this->createStub(TotpAuthenticatorInterface::class);
        $totp->method('checkCode')->willReturn(true);

        $controller = $this->makeController(user: $this->totpUser(), totpAuthenticator: $totp, rateLimitGuard: $guard);

        $controller($this->requestWithSession('123456'));
    }

    public function testRefusesOverTheRateLimitWithoutCheckingTheCode(): void
    {
        $guard = $this->createStub(RateLimitGuardInterface::class);
        $guard->method('consume')->willThrowException(new TooManyRequestsHttpException(60, 'three_brs.rate_limit.too_many_requests'));

        $totp = $this->createMock(TotpAuthenticatorInterface::class);
        $totp->expects(self::never())->method('checkCode');

        $recorder = new Recorder();
        $controller = $this->makeController(
            user: $this->totpUser(),
            totpAuthenticator: $totp,
            rateLimitGuard: $guard,
            recorder: $recorder,
        );

        $request = $this->requestWithSession('123456');
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/two-factor', $response->getTargetUrl());
        self::assertArrayNotHasKey('disabledUser', $recorder);
        self::assertSame(['three_brs.rate_limit.too_many_requests'], $this->flashes($request, 'error'));
    }

    public function testRateLimitGuardNeedsTheGroupFromTheSubclass(): void
    {
        $controller = $this->makeController(
            user: $this->totpUser(),
            totpAuthenticator: $this->createStub(TotpAuthenticatorInterface::class),
            rateLimitGuard: $this->createStub(RateLimitGuardInterface::class),
            rateLimitGroup: null,
        );

        $this->expectException(\LogicException::class);
        $controller($this->requestWithSession('123456'));
    }

    protected function requestWithSession(?string $code = null): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        if ($code !== null) {
            $request->request->set('_code', $code);
        }

        return $request;
    }

    /**
     * @return array<mixed>
     */
    protected function flashes(Request $request, string $type): array
    {
        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);

        return $session->getFlashBag()->peek($type);
    }

    protected function totpUser(): DisableTestTotpUserInterface
    {
        $user = $this->createStub(DisableTestTotpUserInterface::class);
        $user->method('isTotpAuthenticationEnabled')->willReturn(true);
        $user->method('getUserIdentifier')->willReturn('user-id');

        return $user;
    }

    /**
     * @param \ArrayObject<string, mixed>|null $recorder records the user disableTwoFactorAndCommit() was called with
     */
    protected function makeController(
        bool $twoFactorCapable = true,
        bool $csrfValid = true,
        ?UserInterface $user = null,
        ?TotpAuthenticatorInterface $totpAuthenticator = null,
        ?RateLimitGuardInterface $rateLimitGuard = null,
        ?\ArrayObject $recorder = null,
        ?string $validRecoveryCode = null,
        ?string $rateLimitGroup = 'customer',
        ?TokenInterface $token = null,
        bool $withoutGuard = false,
    ): AbstractTwoFactorDisableController {
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        if ($token === null) {
            $token = $this->createStub(TokenInterface::class);
            $token->method('getUser')->willReturn($user ?? $this->createStub(UserInterface::class));
        }

        if ($totpAuthenticator !== null && $rateLimitGuard === null && ! $withoutGuard) {
            $rateLimitGuard = $this->createStub(RateLimitGuardInterface::class);
        }

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $router = $this->createStub(RouterInterface::class);

        return new class($tokenStorage, $csrf, $router, $totpAuthenticator, $rateLimitGuard, $twoFactorCapable, $recorder ?? new Recorder(), $validRecoveryCode, $rateLimitGroup) extends AbstractTwoFactorDisableController {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                CsrfTokenManagerInterface $csrf,
                RouterInterface $router,
                ?TotpAuthenticatorInterface $totpAuthenticator,
                ?RateLimitGuardInterface $rateLimitGuard,
                protected bool $twoFactorCapable,
                protected \ArrayObject $recorder,
                protected ?string $validRecoveryCode,
                protected ?string $rateLimitGroup,
            ) {
                parent::__construct($tokenStorage, $csrf, $router, $totpAuthenticator, $rateLimitGuard);
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
                $this->recorder['disabledUser'] = $user;
            }

            protected function verifyRecoveryCode(UserInterface $user, string $code): bool
            {
                return $this->validRecoveryCode !== null && $code === $this->validRecoveryCode;
            }

            protected function getRateLimitGroup(): string
            {
                return $this->rateLimitGroup ?? parent::getRateLimitGroup();
            }

            protected function getLoginUrl(): string
            {
                return '/login';
            }

            protected function getRedirectAfterDisableUrl(): string
            {
                return '/dashboard';
            }

            protected function getRedirectAfterRefusedCodeUrl(): string
            {
                return '/two-factor';
            }
        };
    }
}
