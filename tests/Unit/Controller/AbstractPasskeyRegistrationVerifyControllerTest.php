<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyRegistrationVerifyController;

#[CoversClass(AbstractPasskeyRegistrationVerifyController::class)]
class AbstractPasskeyRegistrationVerifyControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testThrowsAccessDeniedForBadUser(): void
    {
        $controller = $this->makeController(acceptUser: false);

        $this->expectException(AccessDeniedHttpException::class);
        $controller(new Request());
    }

    public function testReturnsBadRequestOnMissingPayload(): void
    {
        $controller = $this->makeController();
        $response = $controller(new Request());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testReturnsOkOnSuccess(): void
    {
        $controller = $this->makeController();

        $payload = json_encode([
            'credential' => '{"foo":"bar"}',
            'label' => 'My Key',
        ]);
        $request = Request::create('/', 'POST', [], [], [], [], $payload);

        $response = $controller($request);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('{"ok":true}', $response->getContent());
    }

    public function testReturnsBadRequestOnVerificationFailure(): void
    {
        $controller = $this->makeController(verifyThrows: true);

        $payload = json_encode([
            'credential' => '{"foo":"bar"}',
        ]);
        $request = Request::create('/', 'POST', [], [], [], [], $payload);

        $response = $controller($request);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
        bool $verifyThrows = false,
    ): AbstractPasskeyRegistrationVerifyController {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        return new class($tokenStorage, new NullLogger(), $enabled, $acceptUser, $verifyThrows) extends AbstractPasskeyRegistrationVerifyController {
            public function __construct(
                TokenStorageInterface $tokenStorage,
                NullLogger $logger,
                bool $enabled,
                protected bool $acceptUser,
                protected bool $verifyThrows,
            ) {
                parent::__construct($tokenStorage, $logger, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function verifyAndPersist(UserInterface $user, string $credentialJson, string $label, string $host): void
            {
                if ($this->verifyThrows) {
                    throw new \RuntimeException('verify failed');
                }
            }

            protected function getLogChannel(): string
            {
                return 'test.passkey';
            }
        };
    }
}
