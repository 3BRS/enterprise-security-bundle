<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractSessionsListController;
use ThreeBRS\EnterpriseSecurityBundle\Session\SessionRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\Session\UserAgentInfo;
use ThreeBRS\EnterpriseSecurityBundle\Session\UserAgentParserInterface;
use Twig\Environment;

#[CoversClass(AbstractSessionsListController::class)]
class AbstractSessionsListControllerTest extends TestCase
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

    public function testRendersSessions(): void
    {
        $session = $this->createStub(SessionRecordInterface::class);
        $session->method('getUserAgent')->willReturn('test-agent');
        $session->method('getSessionId')->willReturn('s-1');

        $controller = $this->makeController(sessions: [$session]);
        $response = $controller(new Request());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<html/>', $response->getContent());
    }

    /**
     * @param list<SessionRecordInterface> $sessions
     */
    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
        array $sessions = [],
    ): AbstractSessionsListController {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($this->createStub(UserInterface::class));

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $uaParser = $this->createStub(UserAgentParserInterface::class);
        $uaParser->method('parse')->willReturn(new UserAgentInfo('Chrome', 'macOS', 'Desktop'));

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<html/>');

        return new class($tokenStorage, $uaParser, $twig, $enabled, $acceptUser, $sessions) extends AbstractSessionsListController {
            /**
             * @param list<SessionRecordInterface> $sessions
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                UserAgentParserInterface $userAgentParser,
                Environment $twig,
                bool $enabled,
                protected bool $acceptUser,
                protected array $sessions,
            ) {
                parent::__construct($tokenStorage, $userAgentParser, $twig, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function findActiveSessionsForUser(UserInterface $user): iterable
            {
                return $this->sessions;
            }

            protected function getTemplate(): string
            {
                return '@Foo/sessions.html.twig';
            }
        };
    }
}
