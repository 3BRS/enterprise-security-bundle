<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Twig\Environment;

abstract class AbstractMagicLinkRequestController
{
    use FlashHelperTrait;

    public function __construct(
        protected RouterInterface $router,
        protected Environment $twig,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        $form = $this->createForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $this->dispatchFromForm($form);

            $this->addFlashMessage($request, 'success', 'three_brs.ui.magic_link.request_sent');

            return new RedirectResponse($this->router->generate($this->getRedirectRoute()));
        }

        return new Response($this->twig->render($this->getTemplate(), [
            'form' => $form->createView(),
        ]));
    }

    /**
     * @return FormInterface<mixed>
     */
    abstract protected function createForm(): FormInterface;

    /**
     * @param FormInterface<mixed> $form
     */
    abstract protected function dispatchFromForm(FormInterface $form): void;

    abstract protected function getRedirectRoute(): string;

    abstract protected function getTemplate(): string;
}
