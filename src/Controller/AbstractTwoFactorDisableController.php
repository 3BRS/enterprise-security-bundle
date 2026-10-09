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

/**
 * Needs a full sign-in (FullSignInGuardTrait), so a sign-in restored from a remember-me cookie cannot
 * switch the second factor off.
 */
abstract class AbstractTwoFactorDisableController
{
    use FlashHelperTrait;
    use FullSignInGuardTrait;
    use TwoFactorCodeConfirmationTrait;

    /**
     * With $totpAuthenticator, disabling takes the current TOTP code, or a recovery code accepted by
     * verifyRecoveryCode() (TwoFactorCodeConfirmationTrait); without it, the CSRF token alone.
     * $rateLimitGuard counts the code attempts and is required together with $totpAuthenticator.
     */
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected ?TotpAuthenticatorInterface $totpAuthenticator = null,
        protected ?RateLimitGuardInterface $rateLimitGuard = null,
    ) {
        $this->assertRateLimitGuardWithTotpAuthenticator();
    }

    public function __invoke(Request $request): Response
    {
        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();
        if (! $user instanceof UserInterface || ! $this->isFullSignIn($token) || ! $this->isTwoFactorCapableUser($user)) {
            return new RedirectResponse($this->getLoginUrl());
        }

        $submittedToken = (string) $request->request->get('_csrf_token', '');
        if (! $this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $submittedToken))) {
            throw new BadRequestHttpException('Invalid CSRF token.');
        }

        $refusal = $this->confirmCode($request, $user);
        if ($refusal !== null) {
            return $refusal;
        }

        $this->disableTwoFactorAndCommit($user);
        $this->clearCodeAttempts($user);
        $this->addFlashMessage($request, 'success', 'three_brs.two_factor.disabled');

        return new RedirectResponse($this->getRedirectAfterDisableUrl());
    }

    protected function getRedirectAfterRefusedCodeUrl(): string
    {
        return $this->getRedirectAfterDisableUrl();
    }

    abstract protected function getCsrfTokenId(): string;

    abstract protected function isTwoFactorCapableUser(UserInterface $user): bool;

    /**
     * Clear TOTP secret, disable 2FA, bump trusted-device version, delete recovery codes,
     * flush. A subclass owns the entity manager + recovery-code repository.
     */
    abstract protected function disableTwoFactorAndCommit(UserInterface $user): void;

    abstract protected function getLoginUrl(): string;

    abstract protected function getRedirectAfterDisableUrl(): string;
}
