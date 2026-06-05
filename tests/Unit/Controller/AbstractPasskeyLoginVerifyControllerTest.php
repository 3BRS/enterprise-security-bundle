<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\NullLogger;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
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

    public function testReturnsOkOnSuccess(): void
    {
        $user = $this->createStub(UserInterface::class);

        $result = $this->createStub(PasskeyAssertionResultInterface::class);
        $result->method('getUser')->willReturn($user);
        $result->method('isUserVerified')->willReturn(true);

        $verifier = $this->createStub(PasskeyAssertionVerifierInterface::class);
        $verifier->method('verify')->willReturn($result);

        $controller = $this->makeController(verifier: $verifier);
        $request = Request::create('/', 'POST', [], [], [], [], json_encode([
            'credential' => '{}',
        ]));

        $response = $controller($request);

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    protected function makeController(
        bool $enabled = true,
        ?PasskeyAssertionVerifierInterface $verifier = null,
    ): AbstractPasskeyLoginVerifyController {
        $verifier ??= $this->createStub(PasskeyAssertionVerifierInterface::class);

        $eventDispatcher = $this->createStub(EventDispatcherInterface::class);
        $eventDispatcher->method('dispatch')->willReturnCallback(static fn (AuthenticationTokenCreatedEvent $e) => $e);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/dashboard');

        return new class($verifier, $this->createStub(TokenStorageInterface::class), $eventDispatcher, $this->createStub(AuthenticationRequiredHandlerInterface::class), $router, new NullLogger(), $enabled, false) extends AbstractPasskeyLoginVerifyController {
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
