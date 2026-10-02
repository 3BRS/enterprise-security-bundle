<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Decorates scheb's security.authentication.authentication_required_handler.two_factor.<firewall>, which
 * runs after the password and for every page a sign-in waiting for its two-factor code may not open.
 * When the canceller cancels the sign-in, the requested page is opened again, now without it; otherwise
 * scheb's handler sends the user to the code page.
 */
class CancelPendingSignInRequiredHandler implements CancelPendingSignInRequiredHandlerInterface
{
    public function __construct(
        protected AuthenticationRequiredHandlerInterface $inner,
        protected PendingSignInCancellerInterface $pendingSignInCanceller,
    ) {
    }

    public function onAuthenticationRequired(Request $request, TokenInterface $token): Response
    {
        if ($this->pendingSignInCanceller->cancelOnPageLoad($request)) {
            return new RedirectResponse($request->getRequestUri());
        }

        return $this->inner->onAuthenticationRequired($request, $token);
    }
}
