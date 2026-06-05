<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;

abstract class AbstractAccountDeletionRequestController
{
    use FlashHelperTrait;

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected UserPasswordHasherInterface $passwordHasher,
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

        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            throw new NotFoundHttpException();
        }

        if (! $this->hasDeletableSubject($user)) {
            throw new NotFoundHttpException();
        }

        $form = $this->createDeletionRequestForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $providedPassword = (string) $form->get('currentPassword')->getData();
            if (
                ! $user instanceof PasswordAuthenticatedUserInterface
                || ! $this->passwordHasher->isPasswordValid($user, $providedPassword)
            ) {
                $this->addFlashMessage($request, 'error', 'three_brs.account_deletion.invalid_password');

                return new RedirectResponse($this->getRequestFormUrl());
            }

            $this->dispatchDeletionRequest($user);
            $this->tokenStorage->setToken(null);
            $request->getSession()->invalidate();

            $this->addFlashMessage($request, 'success', 'three_brs.account_deletion.requested');

            return new RedirectResponse($this->getPostDeletionUrl());
        }

        return new Response($this->twig->render($this->getTemplate(), [
            'form' => $form->createView(),
        ]));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    /**
     * Confirm that the authenticated user owns a deletable record (e.g. a Sylius
     * Customer linked to the ShopUser). Returns false → 404.
     */
    abstract protected function hasDeletableSubject(UserInterface $user): bool;

    /**
     * @return FormInterface<mixed>
     */
    abstract protected function createDeletionRequestForm(): FormInterface;

    /**
     * Trigger the deletion-request workflow on the plugin's deletion service
     * (typically: resolve the subject record from the user, then call
     * deletionService->requestDeletion(subject)).
     */
    abstract protected function dispatchDeletionRequest(UserInterface $user): void;

    abstract protected function getRequestFormUrl(): string;

    abstract protected function getPostDeletionUrl(): string;

    abstract protected function getTemplate(): string;
}
