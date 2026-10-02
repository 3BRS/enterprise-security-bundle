<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface as TotpTwoFactorInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use ThreeBRS\EnterpriseSecurityBundle\RateLimit\RateLimitGuardInterface;

abstract class AbstractTwoFactorDisableController
{
    use FlashHelperTrait;

    protected const CODE_PARAMETER = '_code';

    protected const RATE_LIMIT_ACTION = 'two_factor_disable';

    protected const INVALID_CODE_MESSAGE = 'three_brs.two_factor.disable_code_invalid';

    /**
     * With $totpAuthenticator, disabling takes the current TOTP code or a recovery code; without it,
     * the CSRF token alone. $rateLimitGuard counts the code attempts.
     */
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected RouterInterface $router,
        protected ?TotpAuthenticatorInterface $totpAuthenticator = null,
        protected ?RateLimitGuardInterface $rateLimitGuard = null,
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

        if ($this->totpAuthenticator !== null) {
            try {
                $this->rateLimitGuard?->consume($request, $this->getRateLimitGroup(), static::RATE_LIMIT_ACTION, $user->getUserIdentifier());
            } catch (TooManyRequestsHttpException) {
                $this->addFlashMessage($request, 'error', 'three_brs.rate_limit.too_many_requests');

                return new RedirectResponse($this->getRedirectAfterRefusedCodeUrl());
            }

            $code = trim((string) $request->request->get(static::CODE_PARAMETER, ''));
            if (! $this->isValidCode($user, $code)) {
                $this->addFlashMessage($request, 'error', static::INVALID_CODE_MESSAGE);

                return new RedirectResponse($this->getRedirectAfterRefusedCodeUrl());
            }
        }

        $this->disableTwoFactorAndCommit($user);
        $this->addFlashMessage($request, 'success', 'three_brs.two_factor.disabled');

        return new RedirectResponse($this->getRedirectAfterDisableUrl());
    }

    protected function isValidCode(UserInterface $user, string $code): bool
    {
        if ($code === '') {
            return false;
        }

        if (
            $this->totpAuthenticator !== null
            && $user instanceof TotpTwoFactorInterface
            && $user->isTotpAuthenticationEnabled()
            && $this->totpAuthenticator->checkCode($user, $code)
        ) {
            return true;
        }

        return $this->verifyRecoveryCode($user, $code);
    }

    /**
     * Override to accept one of the user's unused recovery codes. Nothing needs to be consumed:
     * disableTwoFactorAndCommit() deletes them all.
     */
    protected function verifyRecoveryCode(UserInterface $user, string $code): bool
    {
        return false;
    }

    /**
     * The group (`customer` or `admin`) whose `rate_limit.two_factor_disable.*` settings count the code
     * attempts. Override it when passing a rate-limit guard.
     */
    protected function getRateLimitGroup(): string
    {
        throw new \LogicException(sprintf('%s must override getRateLimitGroup() to count code attempts with a rate-limit guard.', static::class));
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
