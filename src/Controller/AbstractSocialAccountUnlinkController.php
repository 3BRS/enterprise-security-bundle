<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

abstract class AbstractSocialAccountUnlinkController
{
    use FlashHelperTrait;

    public function __construct(
        protected Security $security,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected LoggerInterface $logger,
    ) {
    }

    public function __invoke(Request $request, string $provider): Response
    {
        $user = $this->security->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            throw new AccessDeniedException();
        }

        $submittedToken = (string) $request->request->get('_csrf_token');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId($provider), $submittedToken))) {
            throw new AccessDeniedException('Invalid CSRF token.');
        }

        if (! $this->canUnlinkProvider($user, $provider)) {
            $this->logger->info($this->getAuditChannel() . '.unlink_refused_last_method', [
                'provider' => $provider,
                $this->getAuditUserIdKey() => $user->getUserIdentifier(),
                'ip' => $request->getClientIp(),
            ]);
            $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.cannot_unlink_last_method');

            return new RedirectResponse($this->getSocialAccountsUrl());
        }

        if ($this->deleteLinkForProvider($user, $provider)) {
            $this->logger->info($this->getAuditChannel() . '.unlinked', [
                'provider' => $provider,
                $this->getAuditUserIdKey() => $user->getUserIdentifier(),
                'ip' => $request->getClientIp(),
            ]);
            $this->addFlashMessage($request, 'success', 'three_brs.ui.social_login.unlinked');
        }

        return new RedirectResponse($this->getSocialAccountsUrl());
    }

    abstract protected function getCsrfTokenId(string $provider): string;

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function canUnlinkProvider(UserInterface $user, string $provider): bool;

    /**
     * @return bool true if a link was deleted
     */
    abstract protected function deleteLinkForProvider(UserInterface $user, string $provider): bool;

    abstract protected function getSocialAccountsUrl(): string;

    abstract protected function getAuditChannel(): string;

    abstract protected function getAuditUserIdKey(): string;
}
