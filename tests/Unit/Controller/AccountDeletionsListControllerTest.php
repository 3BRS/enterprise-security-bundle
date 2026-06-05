<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\CustomerDeletionRequestRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\CustomerDeletionRequestRepositoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AccountDeletionsListController;
use Twig\Environment;

#[CoversClass(AccountDeletionsListController::class)]
class AccountDeletionsListControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $repository = $this->createStub(CustomerDeletionRequestRepositoryInterface::class);
        $twig = $this->createStub(Environment::class);

        $controller = new AccountDeletionsListController($repository, $twig, '@Foo/deletions.html.twig', false);

        $this->expectException(NotFoundHttpException::class);
        $controller();
    }

    public function testRendersTemplateWithPendingRequests(): void
    {
        $requests = [
            $this->createStub(CustomerDeletionRequestRecordInterface::class),
            $this->createStub(CustomerDeletionRequestRecordInterface::class),
        ];

        $repository = $this->createStub(CustomerDeletionRequestRepositoryInterface::class);
        $repository->method('findPendingForAdmin')->willReturn($requests);

        $twig = $this->createMock(Environment::class);
        $twig->expects(self::once())
            ->method('render')
            ->with('@Foo/deletions.html.twig', [
                'pendingRequests' => $requests,
            ])
            ->willReturn('<html/>');

        $controller = new AccountDeletionsListController($repository, $twig, '@Foo/deletions.html.twig', true);

        $response = $controller();

        self::assertSame('<html/>', $response->getContent());
    }
}
