<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\NullLogger;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
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

    public function testRedirectsToDashboardOnSuccess(): void
    {
        $magicLink = $this->createStub(MagicLinkRecordInterface::class);

        $verifier = $this->createStub(MagicLinkTokenVerifierInterface::class);
        $verifier->method('verify')->willReturn($magicLink);

        $controller = $this->makeController(verifier: $verifier);
        $response = $controller($this->requestWithSession(), 'good-token');

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
        bool $enabled = true,
        ?MagicLinkTokenVerifierInterface $verifier = null,
    ): AbstractMagicLinkVerifyController {
        $verifier ??= $this->createStub(MagicLinkTokenVerifierInterface::class);

        $eventDispatcher = $this->createStub(EventDispatcherInterface::class);
        $eventDispatcher->method('dispatch')->willReturnCallback(static fn (AuthenticationTokenCreatedEvent $e) => $e);

        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable());

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturnMap([
            ['/dashboard', [], 1, '/dashboard'],
            ['/magic-link/request', [], 1, '/magic-link/request'],
        ]);
        $router->method('generate')->willReturn('/dashboard');

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(null);

        return new class($verifier, $tokenStorage, $eventDispatcher, $this->createStub(AuthenticationRequiredHandlerInterface::class), $router, $clock, new NullLogger(), $enabled) extends AbstractMagicLinkVerifyController {
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
