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
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;

abstract class AbstractTwoFactorRegenerateRecoveryCodesController
{
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected RecoveryCodeGeneratorInterface $recoveryGenerator,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected bool $recoveryCodesEnabled,
        protected int $recoveryCodesCount,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isTwoFactorEnabledUser($user)) {
            return new RedirectResponse($this->getLoginUrl());
        }

        if (! $this->isRecoveryCodesEnabled()) {
            return new RedirectResponse($this->getDashboardUrl());
        }

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $plainCodes = $this->recoveryGenerator->generate($this->getRecoveryCodesCount());
        $this->replaceRecoveryCodesAndCommit($user, $plainCodes);

        $request->getSession()->set($this->getPlainRecoveryCodesSessionKey(), $plainCodes);

        return new RedirectResponse($this->getRecoveryCodesDisplayUrl());
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function isTwoFactorEnabledUser(UserInterface $user): bool;

    /**
     * Delete previous recovery codes and persist hashes of the supplied plain codes.
     * Plugin subclass owns the entity manager + recovery-code repository + entity factory.
     *
     * @param array<int, string> $plainCodes
     */
    abstract protected function replaceRecoveryCodesAndCommit(UserInterface $user, array $plainCodes): void;

    abstract protected function getPlainRecoveryCodesSessionKey(): string;

    abstract protected function getLoginUrl(): string;

    abstract protected function getDashboardUrl(): string;

    abstract protected function getRecoveryCodesDisplayUrl(): string;

    /**
     * Subclass may override to read the toggle at runtime (e.g. from DB-backed
     * settings) rather than the constructor parameter passed at compile time.
     */
    protected function isRecoveryCodesEnabled(): bool
    {
        return $this->recoveryCodesEnabled;
    }

    protected function getRecoveryCodesCount(): int
    {
        return $this->recoveryCodesCount;
    }
}
