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
use ThreeBRS\EnterpriseSecurityBundle\Session\SessionRecordInterface;

abstract class AbstractSessionRevokeController
{
    use FlashHelperTrait;

    public const CSRF_TOKEN_ID = 'three_brs_revoke_session';

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

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken(static::CSRF_TOKEN_ID, $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            throw new AccessDeniedHttpException();
        }

        $session = $this->findSessionForUser($id, $user);
        if ($session === null) {
            throw new NotFoundHttpException();
        }

        $currentSessionId = $request->hasSession() ? $request->getSession()->getId() : '';
        if ($currentSessionId !== '' && $session->getSessionId() === $currentSessionId) {
            $this->addFlashMessage($request, 'error', 'three_brs.session.cannot_revoke_current');

            return new RedirectResponse($this->getSessionsListUrl($request));
        }

        $this->revokeSession($session);
        $this->addFlashMessage($request, 'success', 'three_brs.session.revoked');

        return new RedirectResponse($this->getSessionsListUrl($request));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function findSessionForUser(int $id, UserInterface $user): ?SessionRecordInterface;

    abstract protected function revokeSession(SessionRecordInterface $session): void;

    abstract protected function getSessionsListUrl(Request $request): string;
}
