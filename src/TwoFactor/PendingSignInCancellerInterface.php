<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;

interface PendingSignInCancellerInterface
{
    /**
     * Listens to scheb's TwoFactorAuthenticationEvents::FORM.
     */
    public function markCodePageShown(TwoFactorAuthenticationEvent $event): void;

    /**
     * Listens to kernel.request after the firewall, for the pages scheb lets through as PUBLIC_ACCESS.
     */
    public function cancelOnPublicPage(RequestEvent $event): void;

    /**
     * Cancels the firewall's sign-in that waits for its two-factor code when the request opens another
     * page, and returns whether it did.
     */
    public function cancelOnPageLoad(Request $request): bool;
}
