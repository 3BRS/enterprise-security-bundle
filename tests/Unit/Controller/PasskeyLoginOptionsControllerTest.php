<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\Controller\PasskeyLoginOptionsController;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionOptionsBuilderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use Webauthn\PublicKeyCredentialRequestOptions;

#[CoversClass(PasskeyLoginOptionsController::class)]
class PasskeyLoginOptionsControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = new PasskeyLoginOptionsController(
            $this->createStub(PasskeyAssertionOptionsBuilderInterface::class),
            $this->createStub(PasskeyWebauthnSerializerInterface::class),
            enabled: false,
        );

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testReturnsJsonResponseWithSerializedOptions(): void
    {
        $options = PublicKeyCredentialRequestOptions::create(random_bytes(32));

        $builder = $this->createStub(PasskeyAssertionOptionsBuilderInterface::class);
        $builder->method('build')->willReturn($options);

        $serializer = $this->createMock(PasskeyWebauthnSerializerInterface::class);
        $serializer->expects(self::once())
            ->method('serialize')
            ->with($options)
            ->willReturn('{"challenge":"abc"}');

        $controller = new PasskeyLoginOptionsController($builder, $serializer, enabled: true);
        $response = $controller(new Request());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame('{"challenge":"abc"}', $response->getContent());
    }
}
