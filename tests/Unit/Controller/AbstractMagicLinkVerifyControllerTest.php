<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractMagicLinkVerifyController;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenVerifierInterface;

#[CoversClass(AbstractMagicLinkVerifyController::class)]
class AbstractMagicLinkVerifyControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller($this->requestWithSession(), 'token');
    }

    public function testRedirectsToRequestUrlOnInvalidToken(): void
    {
        $verifier = $this->createStub(MagicLinkTokenVerifierInterface::class);
        $verifier->method('verify')->willReturn(null);

        $controller = $this->makeController(verifier: $verifier);
        $response = $controller($this->requestWithSession(), 'bad-token');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/magic-link/request', $response->getTargetUrl());
    }

    public function testRedirectsToDashboardOnSuccessWithoutTwoFactorChallenge(): void
    {
        $magicLink = $this->createStub(MagicLinkRecordInterface::class);

        $verifier = $this->createStub(MagicLinkTokenVerifierInterface::class);
        $verifier->method('verify')->willReturn($magicLink);

        $controller = $this->makeController(verifier: $verifier);
        $response = $controller($this->requestWithSession(), 'good-token');

        // Magic-link login authenticates directly and lands on the dashboard — it
        // never routes through scheb's two-factor challenge (2FA guards plain
        // password login only).
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
    }

    public function testRefusesADisabledAccountWithoutConsumingTheLink(): void
    {
        // The account is only disabled for now — once it is enabled again, the link must still work.
        $magicLink = $this->createMock(MagicLinkRecordInterface::class);
        $magicLink->expects(self::never())->method('setUsedAt');

        $verifier = $this->createStub(MagicLinkTokenVerifierInterface::class);
        $verifier->method('verify')->willReturn($magicLink);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(null);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            verifier: $verifier,
            userChecker: $this->refusingUserChecker(),
            tokenStorage: $tokenStorage,
        );

        $request = $this->requestWithSession();
        $response = $controller($request, 'good-token');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/magic-link/request', $response->getTargetUrl());
        self::assertSame(
            ['three_brs.account_state.sign_in_refused'],
            $request->getSession()->getFlashBag()->peek('error'),
        );
    }

    protected function refusingUserChecker(): UserCheckerInterface
    {
        $userChecker = $this->createStub(UserCheckerInterface::class);
        $userChecker->method('checkPreAuth')->willThrowException(new DisabledException());

        return $userChecker;
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    protected function makeController(
        bool $enabled = true,
        ?MagicLinkTokenVerifierInterface $verifier = null,
        ?UserCheckerInterface $userChecker = null,
        ?TokenStorageInterface $tokenStorage = null,
    ): AbstractMagicLinkVerifyController {
        $verifier ??= $this->createStub(MagicLinkTokenVerifierInterface::class);
        $userChecker ??= $this->createStub(UserCheckerInterface::class);

        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable());

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/dashboard');

        if ($tokenStorage === null) {
            $tokenStorage = $this->createStub(TokenStorageInterface::class);
            $tokenStorage->method('getToken')->willReturn(null);
        }

        return new class($verifier, $tokenStorage, $router, $clock, new NullLogger(), $enabled, $userChecker) extends AbstractMagicLinkVerifyController {
            protected function isFullyAuthenticatedUser(?TokenInterface $token): bool
            {
                return false;
            }

            protected function getUserFromMagicLink(MagicLinkRecordInterface $magicLink): UserInterface
            {
                return new TestUser();
            }

            protected function commitMagicLinkUsage(MagicLinkRecordInterface $magicLink): void
            {
            }

            protected function getFirewallName(): string
            {
                return 'shop';
            }

            protected function getDefaultRedirectUrl(): string
            {
                return '/dashboard';
            }

            protected function getMagicLinkRequestUrl(): string
            {
                return '/magic-link/request';
            }

            protected function getLogChannel(): string
            {
                return 'test.magic_link';
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }
        };
    }
}
