<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\Controller\LockedUsersListController;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockedUserRepositoryInterface;
use Twig\Environment;

#[CoversClass(LockedUsersListController::class)]
class LockedUsersListControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $repository = $this->createStub(LockedUserRepositoryInterface::class);
        $twig = $this->createStub(Environment::class);

        $controller = new LockedUsersListController($repository, $twig, '@Foo/locked.html.twig', false);

        $this->expectException(NotFoundHttpException::class);
        $controller();
    }

    public function testRendersTemplateWithLockedUsers(): void
    {
        $users = [new \stdClass(), new \stdClass()];

        $repository = $this->createStub(LockedUserRepositoryInterface::class);
        $repository->method('findAllLocked')->willReturn($users);

        $twig = $this->createMock(Environment::class);
        $twig->expects(self::once())
            ->method('render')
            ->with('@Foo/locked.html.twig', [
                'users' => $users,
            ])
            ->willReturn('<html/>');

        $controller = new LockedUsersListController($repository, $twig, '@Foo/locked.html.twig', true);

        $response = $controller();

        self::assertSame('<html/>', $response->getContent());
    }
}
