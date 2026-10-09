<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuardInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;

/**
 * Needs a full sign-in (FullSignInGuardTrait): the new recovery codes pass the second factor, so a
 * sign-in restored from a remember-me cookie must not obtain them.
 */
abstract class AbstractTwoFactorRegenerateRecoveryCodesController
{
    use FlashHelperTrait;
    use FullSignInGuardTrait;
    use TwoFactorCodeConfirmationTrait;

    /**
     * With $totpAuthenticator, regenerating takes the current TOTP code, or a recovery code accepted by
     * verifyRecoveryCode() (TwoFactorCodeConfirmationTrait); without it, the CSRF token alone. A new
     * recovery code would otherwise confirm switching 2FA off. $rateLimitGuard counts the code attempts
     * and is required together with $totpAuthenticator.
     */
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected RecoveryCodeGeneratorInterface $recoveryGenerator,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected bool $recoveryCodesEnabled,
        protected int $recoveryCodesCount,
        protected ?TotpAuthenticatorInterface $totpAuthenticator = null,
        protected ?RateLimitGuardInterface $rateLimitGuard = null,
    ) {
        $this->assertRateLimitGuardWithTotpAuthenticator();
    }

    public function __invoke(Request $request): Response
    {
        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();
        if (! $user instanceof UserInterface || ! $this->isFullSignIn($token) || ! $this->isTwoFactorEnabledUser($user)) {
            return new RedirectResponse($this->getLoginUrl());
        }

        if (! $this->isRecoveryCodesEnabled()) {
            return new RedirectResponse($this->getDashboardUrl());
        }

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $refusal = $this->confirmCode($request, $user);
        if ($refusal !== null) {
            return $refusal;
        }

        $plainCodes = $this->recoveryGenerator->generate($this->getRecoveryCodesCount());
        $this->replaceRecoveryCodesAndCommit($user, $plainCodes);
        $this->clearCodeAttempts($user);

        $request->getSession()->set($this->getPlainRecoveryCodesSessionKey(), $plainCodes);

        return new RedirectResponse($this->getRecoveryCodesDisplayUrl());
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function isTwoFactorEnabledUser(UserInterface $user): bool;

    /**
     * Delete previous recovery codes and persist hashes of the supplied plain codes.
     * A subclass owns the entity manager + recovery-code repository + entity factory.
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

    protected function getRedirectAfterRefusedCodeUrl(): string
    {
        return $this->getDashboardUrl();
    }
}
