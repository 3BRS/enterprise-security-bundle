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

    /**
     * Flashed when the confirmation fails. Override it along with isDeletionConfirmed().
     */
    protected const NOT_CONFIRMED_MESSAGE = 'three_brs.account_deletion.invalid_password';

    /**
     * The field isDeletionConfirmed() reads by default.
     */
    protected const PASSWORD_FIELD = 'currentPassword';

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
            if (! $this->isDeletionConfirmed($form, $user)) {
                $this->addFlashMessage($request, 'error', static::NOT_CONFIRMED_MESSAGE);

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

    /**
     * Re-authentication before an irreversible request. The current password is the default, but it
     * is not available to every account: one created by a social sign-up has no password at all, and
     * a consumer that has turned password sign-in off has no field to ask for it in. Such a consumer
     * overrides this with whatever confirmation it does have (an acknowledgement, an emailed code).
     *
     * @param FormInterface<mixed> $form
     */
    protected function isDeletionConfirmed(FormInterface $form, UserInterface $user): bool
    {
        // Refused rather than fatal when the form carries no password field: a consumer that dropped
        // the field is expected to override this method, and a 500 would be a poor way to say so.
        if (! $form->has(static::PASSWORD_FIELD)) {
            return false;
        }

        $providedPassword = (string) $form->get(static::PASSWORD_FIELD)->getData();

        return $user instanceof PasswordAuthenticatedUserInterface
            && $this->passwordHasher->isPasswordValid($user, $providedPassword);
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    /**
     * Confirm that the authenticated user owns a deletable record (e.g. the customer record linked
     * to the account). Returns false → 404.
     */
    abstract protected function hasDeletableSubject(UserInterface $user): bool;

    /**
     * @return FormInterface<mixed>
     */
    abstract protected function createDeletionRequestForm(): FormInterface;

    /**
     * Trigger the deletion-request workflow on the consumer's deletion service
     * (typically: resolve the subject record from the user, then call
     * deletionService->requestDeletion(subject)).
     */
    abstract protected function dispatchDeletionRequest(UserInterface $user): void;

    abstract protected function getRequestFormUrl(): string;

    abstract protected function getPostDeletionUrl(): string;

    abstract protected function getTemplate(): string;
}
