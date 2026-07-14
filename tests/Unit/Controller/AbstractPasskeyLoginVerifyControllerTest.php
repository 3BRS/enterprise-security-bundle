<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyLoginVerifyController;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionResultInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionVerifierInterface;

#[CoversClass(AbstractPasskeyLoginVerifyController::class)]
class AbstractPasskeyLoginVerifyControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testReturnsBadRequestOnMissingPayload(): void
    {
        $controller = $this->makeController();
        $response = $controller(new Request());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testReturnsBadRequestOnVerifierException(): void
    {
        $verifier = $this->createStub(PasskeyAssertionVerifierInterface::class);
        $verifier->method('verify')->willThrowException(new \RuntimeException('bad'));

        $controller = $this->makeController(verifier: $verifier);
        $request = Request::create('/', 'POST', [], [], [], [], json_encode([
            'credential' => '{}',
        ]));

        $response = $controller($request);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testReturnsOkOnSuccessWithoutTwoFactorChallenge(): void
    {
        $user = $this->createStub(UserInterface::class);

        $result = $this->createStub(PasskeyAssertionResultInterface::class);
        $result->method('getUser')->willReturn($user);

        $verifier = $this->createStub(PasskeyAssertionVerifierInterface::class);
        $verifier->method('verify')->willReturn($result);

        $controller = $this->makeController(verifier: $verifier);
        $request = Request::create('/', 'POST', [], [], [], [], json_encode([
            'credential' => '{}',
        ]));

        $response = $controller($request);

        // Passkey login authenticates directly and returns the dashboard redirect —
        // it never routes through scheb's two-factor challenge (2FA guards plain
        // password login only).
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    public function testRefusesADisabledAccountWithoutAuthenticating(): void
    {
        $result = $this->createStub(PasskeyAssertionResultInterface::class);
        $result->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $verifier = $this->createStub(PasskeyAssertionVerifierInterface::class);
        $verifier->method('verify')->willReturn($result);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('setToken');

        $controller = $this->makeController(
            verifier: $verifier,
            userChecker: $this->refusingUserChecker(),
            tokenStorage: $tokenStorage,
        );

        $request = Request::create('/', 'POST', [], [], [], [], json_encode([
            'credential' => '{}',
        ]));

        $response = $controller($request);

        // The sign-in button's fetch() gets a status and a body it can act on; no token is written.
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        self::assertJsonStringEqualsJsonString(
            (string) json_encode([
                'error' => 'Account is not allowed to sign in.',
            ]),
            (string) $response->getContent(),
        );
    }

    protected function refusingUserChecker(): UserCheckerInterface
    {
        $userChecker = $this->createStub(UserCheckerInterface::class);
        $userChecker->method('checkPreAuth')->willThrowException(new DisabledException());

        return $userChecker;
    }

    protected function makeController(
        bool $enabled = true,
        ?PasskeyAssertionVerifierInterface $verifier = null,
        ?UserCheckerInterface $userChecker = null,
        ?TokenStorageInterface $tokenStorage = null,
    ): AbstractPasskeyLoginVerifyController {
        $verifier ??= $this->createStub(PasskeyAssertionVerifierInterface::class);
        $userChecker ??= $this->createStub(UserCheckerInterface::class);
        $tokenStorage ??= $this->createStub(TokenStorageInterface::class);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/dashboard');

        return new class($verifier, $tokenStorage, $router, new NullLogger(), $enabled, $userChecker) extends AbstractPasskeyLoginVerifyController {
            protected function getFirewallName(): string
            {
                return 'shop';
            }

            protected function getDefaultRedirectUrl(): string
            {
                return '/dashboard';
            }

            protected function getLogChannel(): string
            {
                return 'test.passkey';
            }

            protected function handlePostLogin(UserInterface $user, Request $request): void
            {
            }
        };
    }
}
