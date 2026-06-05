<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractMagicLinkRequestController;
use Twig\Environment;

#[CoversClass(AbstractMagicLinkRequestController::class)]
class AbstractMagicLinkRequestControllerTest extends TestCase
{
    public function testThrowsNotFoundWhenDisabled(): void
    {
        $controller = $this->makeController(enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller(new Request());
    }

    public function testRendersFormOnGet(): void
    {
        $form = $this->createStub(FormInterface::class);
        $form->method('isSubmitted')->willReturn(false);
        $form->method('createView')->willReturn($this->createStub(FormView::class));

        $controller = $this->makeController(form: $form);
        $response = $controller(new Request());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<form/>', $response->getContent());
    }

    /**
     * @param FormInterface<mixed>|null $form
     */
    protected function makeController(
        bool $enabled = true,
        ?FormInterface $form = null,
    ): AbstractMagicLinkRequestController {
        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/magic-link');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturn('<form/>');

        $form ??= $this->createStub(FormInterface::class);

        return new class($router, $twig, $enabled, $form) extends AbstractMagicLinkRequestController {
            /**
             * @param FormInterface<mixed> $form
             */
            public function __construct(
                RouterInterface $router,
                Environment $twig,
                bool $enabled,
                protected FormInterface $form,
            ) {
                parent::__construct($router, $twig, $enabled);
            }

            protected function createForm(): FormInterface
            {
                return $this->form;
            }

            protected function dispatchFromForm(FormInterface $form): void
            {
            }

            protected function getRedirectRoute(): string
            {
                return 'magic_link_request';
            }

            protected function getTemplate(): string
            {
                return '@Foo/magic_link.html.twig';
            }
        };
    }
}
