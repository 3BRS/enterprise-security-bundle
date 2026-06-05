<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

abstract class AbstractUnlockUserController
{
    use FlashHelperTrait;

    public function __construct(
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
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $state = $this->attemptUnlock($id);
        if ($state === null) {
            throw new NotFoundHttpException();
        }

        if ($state) {
            $this->addFlashMessage($request, 'success', 'three_brs.lockout.unlocked');
        } else {
            $this->addFlashMessage($request, 'info', 'three_brs.lockout.already_unlocked');
        }

        return new RedirectResponse($this->getLockedListUrl());
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function getLockedListUrl(): string;

    /**
     * Look up the lockable user by id. Returns:
     *  - null when the user does not exist (controller responds with 404)
     *  - true when the user was unlocked just now
     *  - false when the user was already unlocked (no-op + info flash)
     */
    abstract protected function attemptUnlock(int $id): ?bool;
}
