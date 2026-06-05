<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Controller\SocialAccountsOverviewController;
use Twig\Environment;

#[CoversClass(SocialAccountsOverviewController::class)]
class SocialAccountsOverviewControllerTest extends TestCase
{
    public function testRendersTemplate(): void
    {
        $twig = $this->createMock(Environment::class);
        $twig->expects(self::once())
            ->method('render')
            ->with('@Foo/accounts.html.twig')
            ->willReturn('<html/>');

        $controller = new SocialAccountsOverviewController($twig, '@Foo/accounts.html.twig');

        $response = $controller();

        self::assertSame('<html/>', $response->getContent());
    }
}
