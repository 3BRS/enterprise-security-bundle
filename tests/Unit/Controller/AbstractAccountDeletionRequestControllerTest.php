<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\HttpFoundation\RedirectResponse;
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
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestPasswordUser;
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

    public function testRefusesTheDeletionOnAWrongCurrentPassword(): void
    {
        $recorder = new \ArrayObject();

        $controller = $this->makeController(
            form: $this->submittedForm(hasPasswordField: true, providedPassword: 'wrong'),
            user: new TestPasswordUser(),
            passwordHasher: $this->passwordHasher(isValid: false),
            recorder: $recorder,
        );

        $request = $this->requestWithSession();
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/account-deletion', $response->getTargetUrl());

        // The irreversible request is not made on a failed re-authentication.
        self::assertArrayNotHasKey('dispatched', $recorder);

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains('three_brs.account_deletion.invalid_password', $session->getFlashBag()->peek('error'));
    }

    public function testDispatchesTheDeletionAndSignsTheUserOutOnTheCorrectPassword(): void
    {
        $recorder = new \ArrayObject();
        $user = new TestPasswordUser();

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($this->tokenFor($user));
        $tokenStorage->expects(self::once())->method('setToken')->with(null);

        $controller = $this->makeController(
            form: $this->submittedForm(hasPasswordField: true, providedPassword: 'correct'),
            user: $user,
            passwordHasher: $this->passwordHasher(isValid: true),
            tokenStorage: $tokenStorage,
            recorder: $recorder,
        );

        $request = $this->requestWithSession();
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/', $response->getTargetUrl());

        self::assertArrayHasKey('dispatched', $recorder);
        self::assertSame($user, $recorder['dispatched']);
    }

    public function testHonoursAnOverriddenConfirmationSeamWithoutReadingThePasswordField(): void
    {
        $recorder = new \ArrayObject();
        $user = new TestUser();

        // A consumer that has no password field at all (e.g. password sign-in turned off) confirms
        // the deletion its own way; the default's password lookup must never be reached — the form
        // stub blows up if it is.
        $controller = $this->makeController(
            form: $this->submittedForm(hasPasswordField: false),
            user: $user,
            confirmed: true,
            recorder: $recorder,
        );

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/', $response->getTargetUrl());
        self::assertArrayHasKey('dispatched', $recorder);
        self::assertSame($user, $recorder['dispatched']);
    }

    public function testDefaultConfirmationRefusesWhenTheFormCarriesNoPasswordField(): void
    {
        $recorder = new \ArrayObject();

        // Dropping the field without overriding the seam is a consumer mistake — it must end in a
        // refusal, not a fatal error.
        $controller = $this->makeController(
            form: $this->submittedForm(hasPasswordField: false),
            user: new TestPasswordUser(),
            recorder: $recorder,
        );

        $request = $this->requestWithSession();
        $response = $controller($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/account-deletion', $response->getTargetUrl());
        self::assertArrayNotHasKey('dispatched', $recorder);

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertContains('three_brs.account_deletion.invalid_password', $session->getFlashBag()->peek('error'));
    }

    /**
     * A submitted, valid form. Without the password field, get() throws: the tests that drop the
     * field rely on the default seam refusing before it reads anything.
     *
     * @return FormInterface<mixed>
     */
    protected function submittedForm(bool $hasPasswordField, string $providedPassword = ''): FormInterface
    {
        $form = $this->createStub(FormInterface::class);
        $form->method('isSubmitted')->willReturn(true);
        $form->method('isValid')->willReturn(true);
        $form->method('has')->willReturn($hasPasswordField);
        $form->method('createView')->willReturn($this->createStub(FormView::class));

        if ($hasPasswordField) {
            $field = $this->createStub(FormInterface::class);
            $field->method('getData')->willReturn($providedPassword);
            $form->method('get')->willReturn($field);
        } else {
            $form->method('get')->willThrowException(new \LogicException('The password field must not be read.'));
        }

        return $form;
    }

    protected function passwordHasher(bool $isValid): UserPasswordHasherInterface
    {
        $passwordHasher = $this->createStub(UserPasswordHasherInterface::class);
        $passwordHasher->method('isPasswordValid')->willReturn($isValid);

        return $passwordHasher;
    }

    protected function tokenFor(UserInterface $user): TokenInterface
    {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($user);

        return $token;
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    /**
     * @param FormInterface<mixed>|null $form
     * @param \ArrayObject<string, mixed>|null $recorder records the mutating hooks the controller calls
     */
    protected function makeController(
        bool $enabled = true,
        bool $acceptUser = true,
        bool $hasSubject = true,
        ?FormInterface $form = null,
        ?UserInterface $user = null,
        ?UserPasswordHasherInterface $passwordHasher = null,
        ?TokenStorageInterface $tokenStorage = null,
        ?bool $confirmed = null,
        ?\ArrayObject $recorder = null,
    ): AbstractAccountDeletionRequestController {
        $user ??= new TestUser();
        $recorder ??= new \ArrayObject();
        $passwordHasher ??= $this->createStub(UserPasswordHasherInterface::class);

        if ($tokenStorage === null) {
            $tokenStorage = $this->createStub(TokenStorageInterface::class);
            $tokenStorage->method('getToken')->willReturn($this->tokenFor($user));
        }

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/account-deletion');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        $form ??= $this->createStub(FormInterface::class);

        return new class($tokenStorage, $passwordHasher, $router, $twig, $enabled, $acceptUser, $hasSubject, $form, $confirmed, $recorder) extends AbstractAccountDeletionRequestController {
            /**
             * @param FormInterface<mixed> $form
             * @param \ArrayObject<string, mixed> $recorder
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
                protected ?bool $confirmed,
                protected \ArrayObject $recorder,
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

            protected function isDeletionConfirmed(FormInterface $form, UserInterface $user): bool
            {
                // Left to the parent unless a test stands in for a consumer that overrides the seam.
                return $this->confirmed ?? parent::isDeletionConfirmed($form, $user);
            }

            protected function dispatchDeletionRequest(UserInterface $user): void
            {
                $this->recorder['dispatched'] = $user;
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
