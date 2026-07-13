<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Enforces the account state on passwordless sign-in (magic link, social login, passkey).
 *
 * Those flows write the security token straight into the token storage — bypassing the firewall on
 * purpose, so that the second factor (which guards password sign-in only) is not challenged. The
 * firewall is also what runs the user checker, so without this the account state would only be
 * enforced on the password form: an account disabled by an administrator, or one whose self-service
 * deletion is pending, could sign straight back in through any passwordless method.
 *
 * Bind a checker that looks at the account state alone, not the whole firewall chain: an account
 * locked by failed password attempts has to keep its passwordless way in, otherwise anyone could lock
 * a victim out of their own passkey by guessing their password wrong often enough.
 *
 * Controllers call this before they mutate anything — a refused sign-in must not consume the magic
 * link it came in on, nor create the social-account link it was about to.
 */
trait AccountStateGuardTrait
{
    /**
     * Message key the controllers flash when they turn a refused account away.
     */
    protected const ACCOUNT_REFUSED_MESSAGE = 'three_brs.account_state.sign_in_refused';

    protected UserCheckerInterface $userChecker;

    protected function isAccountAllowedToSignIn(UserInterface $user): bool
    {
        try {
            $this->userChecker->checkPreAuth($user);
        } catch (AccountStatusException) {
            return false;
        }

        return true;
    }
}
