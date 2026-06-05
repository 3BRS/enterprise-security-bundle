<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

abstract class AbstractPasskeyDeleteController
{
    use FlashHelperTrait;

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request, int $id): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            throw new AccessDeniedHttpException();
        }

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $credential = $this->findCredentialForUser($id, $user);
        if ($credential === null) {
            throw new NotFoundHttpException();
        }

        if (! $this->canRemoveCredential($user)) {
            $this->addFlashMessage($request, 'error', 'three_brs.ui.passkey.cannot_remove_last_auth_method');

            return new RedirectResponse($this->getPasskeyListUrl());
        }

        $this->deleteCredential($credential);
        $this->addFlashMessage($request, 'success', 'three_brs.ui.passkey.removed');

        return new RedirectResponse($this->getPasskeyListUrl());
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function findCredentialForUser(int $id, UserInterface $user): ?object;

    abstract protected function canRemoveCredential(UserInterface $user): bool;

    abstract protected function deleteCredential(object $credential): void;

    abstract protected function getPasskeyListUrl(): string;
}
