<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * For the actions that change how the account is signed in to — linking a social account, registering
 * a passkey, setting up, disabling or regenerating the second factor. They need a full sign-in, the one
 * IS_AUTHENTICATED_FULLY grants with Symfony's and scheb's trust resolvers: a sign-in that waits for its
 * two-factor code has only the password behind it, and one restored from a remember-me cookie only the
 * cookie.
 */
trait FullSignInGuardTrait
{
    protected function isFullSignIn(?TokenInterface $token): bool
    {
        return $token?->getUser() !== null
            && ! $token instanceof RememberMeToken
            && ! $token instanceof TwoFactorTokenInterface;
    }
}
