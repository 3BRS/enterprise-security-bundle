<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

abstract class AbstractTwoFactorDisableController
{
    use FlashHelperTrait;

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isTwoFactorCapableUser($user)) {
            return new RedirectResponse($this->getLoginUrl());
        }

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $this->disableTwoFactorAndCommit($user);
        $this->addFlashMessage($request, 'success', 'three_brs.two_factor.disabled');

        return new RedirectResponse($this->getRedirectAfterDisableUrl());
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function isTwoFactorCapableUser(UserInterface $user): bool;

    /**
     * Clear TOTP secret, disable 2FA, bump trusted-device version, delete recovery codes,
     * flush. Plugin subclass owns the entity manager + recovery-code repository.
     */
    abstract protected function disableTwoFactorAndCommit(UserInterface $user): void;

    abstract protected function getLoginUrl(): string;

    abstract protected function getRedirectAfterDisableUrl(): string;
}
