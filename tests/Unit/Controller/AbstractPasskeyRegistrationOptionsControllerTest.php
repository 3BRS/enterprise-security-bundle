<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyRegistrationOptionsController;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

#[CoversClass(AbstractPasskeyRegistrationOptionsController::class)]
class AbstractPasskeyRegistrationOptionsControllerTest extends TestCase
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

    public function testReturnsJsonResponse(): void
    {
        $controller = $this->makeController();
        $response = $controller(new Request());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame('{"opts":1}', $response->getContent());
    }

    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
    ): AbstractPasskeyRegistrationOptionsController {
        $serializer = $this->createStub(PasskeyWebauthnSerializerInterface::class);
        $serializer->method('serialize')->willReturn('{"opts":1}');

        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $rp = new PublicKeyCredentialRpEntity('Example');
        $userEntity = new PublicKeyCredentialUserEntity('user', 'user-id', 'User');
        $options = PublicKeyCredentialCreationOptions::create($rp, $userEntity, random_bytes(32));

        return new class($serializer, $tokenStorage, $enabled, $acceptUser, $options) extends AbstractPasskeyRegistrationOptionsController {
            public function __construct(
                PasskeyWebauthnSerializerInterface $serializer,
                TokenStorageInterface $tokenStorage,
                bool $enabled,
                protected bool $acceptUser,
                protected PublicKeyCredentialCreationOptions $options,
            ) {
                parent::__construct($serializer, $tokenStorage, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function buildRegistrationOptions(UserInterface $user): PublicKeyCredentialCreationOptions
            {
                return $this->options;
            }
        };
    }
}
