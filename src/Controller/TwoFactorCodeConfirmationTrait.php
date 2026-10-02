<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface as TotpTwoFactorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Confirms a change to the second factor — disabling it, regenerating the recovery codes — with the
 * current TOTP code or a recovery code submitted in `_code`. The using controller has the properties
 * `?TotpAuthenticatorInterface $totpAuthenticator` and `?RateLimitGuardInterface $rateLimitGuard` and
 * uses FlashHelperTrait. Without the authenticator no code is asked for. The confirmed actions share
 * one counter, the `two_factor_code` rate-limit action, since every one of them checks the same code.
 */
trait TwoFactorCodeConfirmationTrait
{
    protected const CODE_PARAMETER = '_code';

    protected const RATE_LIMIT_ACTION = 'two_factor_code';

    protected const INVALID_CODE_MESSAGE = 'three_brs.two_factor.confirmation_code_invalid';

    protected function assertRateLimitGuardWithTotpAuthenticator(): void
    {
        if ($this->totpAuthenticator !== null && $this->rateLimitGuard === null) {
            throw new \LogicException(sprintf('%s needs $rateLimitGuard together with $totpAuthenticator; without it the code can be guessed without limit.', static::class));
        }
    }

    /**
     * Returns the response that refuses the request, or null when the code is confirmed or none is
     * asked for. An empty code is refused without being counted towards the limit.
     */
    protected function confirmCode(Request $request, UserInterface $user): ?Response
    {
        if ($this->totpAuthenticator === null) {
            return null;
        }

        $code = trim((string) $request->request->get(static::CODE_PARAMETER, ''));
        if ($code === '') {
            return $this->refuseCode($request, static::INVALID_CODE_MESSAGE);
        }

        try {
            $this->rateLimitGuard?->consume($request, $this->getRateLimitGroup(), static::RATE_LIMIT_ACTION, $user->getUserIdentifier());
        } catch (TooManyRequestsHttpException) {
            return $this->refuseCode($request, 'three_brs.rate_limit.too_many_requests');
        }

        if (! $this->isValidCode($user, $code)) {
            return $this->refuseCode($request, static::INVALID_CODE_MESSAGE);
        }

        return null;
    }

    /**
     * Clears the user's `two_factor_code` counter once the confirmed action is done.
     */
    protected function clearCodeAttempts(UserInterface $user): void
    {
        if ($this->totpAuthenticator !== null) {
            $this->rateLimitGuard?->reset($this->getRateLimitGroup(), static::RATE_LIMIT_ACTION, $user->getUserIdentifier());
        }
    }

    protected function refuseCode(Request $request, string $message): Response
    {
        $this->addFlashMessage($request, 'error', $message);

        return new RedirectResponse($this->getRedirectAfterRefusedCodeUrl());
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
     * Override to accept one of the user's unused recovery codes. Nothing needs to be consumed: the
     * confirmed action deletes or replaces them all.
     */
    protected function verifyRecoveryCode(UserInterface $user, string $code): bool
    {
        return false;
    }

    /**
     * The group (`customer` or `admin`) whose `rate_limit.two_factor_code.*` settings count the code
     * attempts. Override it when passing a rate-limit guard.
     */
    protected function getRateLimitGroup(): string
    {
        throw new \LogicException(sprintf('%s must override getRateLimitGroup() to count code attempts with a rate-limit guard.', static::class));
    }

    abstract protected function getRedirectAfterRefusedCodeUrl(): string;
}
