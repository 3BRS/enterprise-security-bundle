<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractAccountDeletionRequestController;
use Twig\Environment;

#[CoversClass(AbstractAccountDeletionRequestController::class)]
class AbstractAccountDeletionRequestControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller($this->requestWithSession());
    }

    public function testThrowsNotFoundForBadUser(): void
    {
        $controller = $this->makeController(acceptUser: false);

        $this->expectException(NotFoundHttpException::class);
        $controller($this->requestWithSession());
    }

    public function testThrowsNotFoundWithoutDeletableSubject(): void
    {
        $controller = $this->makeController(hasSubject: false);

        $this->expectException(NotFoundHttpException::class);
        $controller($this->requestWithSession());
    }

    public function testRendersFormOnGet(): void
    {
        $form = $this->createStub(FormInterface::class);
        $form->method('isSubmitted')->willReturn(false);
        $form->method('createView')->willReturn($this->createStub(FormView::class));

        $controller = $this->makeController(form: $form);

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    /**
     * @param FormInterface<mixed>|null $form
     */
    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
        bool $hasSubject = true,
        ?FormInterface $form = null,
    ): AbstractAccountDeletionRequestController {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn(new TestUser());

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/account-deletion');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        $form ??= $this->createStub(FormInterface::class);

        return new class($tokenStorage, $this->createStub(UserPasswordHasherInterface::class), $router, $twig, $enabled, $acceptUser, $hasSubject, $form) extends AbstractAccountDeletionRequestController {
            /**
             * @param FormInterface<mixed> $form
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                UserPasswordHasherInterface $passwordHasher,
                RouterInterface $router,
                Environment $twig,
                bool $enabled,
                protected bool $acceptUser,
                protected bool $hasSubject,
                protected FormInterface $form,
            ) {
                parent::__construct($tokenStorage, $passwordHasher, $router, $twig, $enabled);
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function hasDeletableSubject(UserInterface $user): bool
            {
                return $this->hasSubject;
            }

            protected function createDeletionRequestForm(): FormInterface
            {
                return $this->form;
            }

            protected function dispatchDeletionRequest(UserInterface $user): void
            {
            }

            protected function getRequestFormUrl(): string
            {
                return '/account-deletion';
            }

            protected function getPostDeletionUrl(): string
            {
                return '/';
            }

            protected function getTemplate(): string
            {
                return '@Foo/deletion.html.twig';
            }
        };
    }
}
