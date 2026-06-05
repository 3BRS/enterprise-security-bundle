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

abstract class AbstractAccountDeletionCancelController
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

        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken('three_brs_account_deletion_cancel_' . $id, (string) $request->request->get('_token')))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        if (! $this->cancelDeletionRequest($id)) {
            throw new NotFoundHttpException();
        }

        $this->addFlashMessage($request, 'success', 'three_brs.account_deletion.cancelled');

        return new RedirectResponse($this->getDeletionsListUrl());
    }

    /**
     * Load the deletion request, call the deletion service with the current admin,
     * return false when the request does not exist or the admin token is missing
     * (controller responds with 404).
     */
    abstract protected function cancelDeletionRequest(int $id): bool;

    abstract protected function getDeletionsListUrl(): string;
}
