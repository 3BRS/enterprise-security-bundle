<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSignInsThatAreNotFull(): iterable
    {
        yield 'waiting for its two-factor code' => ['two_factor'];
        yield 'restored from a remember-me cookie' => ['remember_me'];
        yield 'none' => ['none'];
    }

    /**
     * A passkey signs in without the second factor, so it must not be added on the password alone or
     * on a remember-me cookie.
     */
    #[DataProvider('provideSignInsThatAreNotFull')]
    public function testRefusesASignInThatIsNotFull(string $signIn): void
    {
        $user = new TestUser();
        $passwordToken = new UsernamePasswordToken($user, 'main', $user->getRoles());

        $rememberMeToken = $this->createStub(RememberMeToken::class);
        $rememberMeToken->method('getUser')->willReturn($user);

        $controller = $this->makeController(token: match ($signIn) {
            'two_factor' => new TwoFactorToken($passwordToken, null, 'main', ['totp']),
            'remember_me' => $rememberMeToken,
            default => new NullToken(),
        });

        $this->expectException(AccessDeniedHttpException::class);
        $controller(new Request());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFullSignIns(): iterable
    {
        yield 'password, code entered or not required' => ['password'];
        yield 'OAuth, magic link or passkey' => ['passwordless'];
    }

    /**
     * The OAuth, magic-link and passkey sign-in controllers write a PostAuthenticationToken, which is a
     * full sign-in like the password form's token once its code was entered.
     */
    #[DataProvider('provideFullSignIns')]
    public function testAcceptsAFullSignIn(string $signIn): void
    {
        $user = new TestUser();
        $controller = $this->makeController(token: match ($signIn) {
            'password' => new UsernamePasswordToken($user, 'main', $user->getRoles()),
            default => new PostAuthenticationToken($user, 'main', $user->getRoles()),
        });

        self::assertInstanceOf(JsonResponse::class, $controller(new Request()));
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
        ?TokenInterface $token = null,
    ): AbstractPasskeyRegistrationOptionsController {
        $serializer = $this->createStub(PasskeyWebauthnSerializerInterface::class);
        $serializer->method('serialize')->willReturn('{"opts":1}');

        if ($token === null) {
            $token = $this->createStub(TokenInterface::class);
            $token->method('getUser')->willReturn($this->createStub(UserInterface::class));
        }

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
