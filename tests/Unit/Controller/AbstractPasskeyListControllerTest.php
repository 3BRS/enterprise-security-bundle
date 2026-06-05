<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractPasskeyListController;
use Twig\Environment;

#[CoversClass(AbstractPasskeyListController::class)]
class AbstractPasskeyListControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(
            tokenStorage: $this->createStub(TokenStorageInterface::class),
            twig: $this->createStub(Environment::class),
            enabled: false,
        );

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testThrowsAccessDeniedWhenUserNotAcceptable(): void
    {
        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(null);

        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            twig: $this->createStub(Environment::class),
            enabled: true,
        );

        $this->expectException(AccessDeniedHttpException::class);
        $controller(new Request());
    }

    public function testRendersCredentialsForAuthenticatedUser(): void
    {
        $credentials = [new \stdClass()];

        $user = $this->createStub(UserInterface::class);
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($user);

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $twig = $this->createMock(Environment::class);
        $twig->expects(self::once())
            ->method('render')
            ->with('@Foo/passkeys.html.twig', [
                'credentials' => $credentials,
            ])
            ->willReturn('<html/>');

        $controller = $this->makeController(
            tokenStorage: $tokenStorage,
            twig: $twig,
            enabled: true,
            acceptUser: true,
            credentials: $credentials,
        );

        $response = $controller(new Request());

        self::assertSame('<html/>', $response->getContent());
    }

    /**
     * @param list<object> $credentials
     */
    protected function makeController(
        TokenStorageInterface $tokenStorage,
        Environment $twig,
        bool $enabled,
        bool $acceptUser = false,
        array $credentials = [],
    ): AbstractPasskeyListController {
        return new class($tokenStorage, $twig, $enabled, $acceptUser, $credentials) extends AbstractPasskeyListController {
            /**
             * @param list<object> $credentials
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                Environment $twig,
                bool $enabled,
                protected bool $acceptUser,
                protected array $credentials,
            ) {
                parent::__construct($tokenStorage, $twig, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function findCredentialsForUser(UserInterface $user): iterable
            {
                return $this->credentials;
            }

            protected function getTemplate(): string
            {
                return '@Foo/passkeys.html.twig';
            }
        };
    }
}
