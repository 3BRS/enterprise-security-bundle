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
 * The bound checker must refuse on the account state alone. That is a precondition on what you bind,
 * not an invariant held here: the refusal below catches `AccountStatusException`, the supertype of
 * `DisabledException`, `LockedException`, `AccountExpiredException` and `CredentialsExpiredException`
 * alike, so whatever the bound checker throws closes the passwordless routes. Bind your firewall's
 * chain and a `LockedException` from failed password attempts would close them too — anyone could
 * then lock a victim out of their own passkey by guessing their password wrong often enough. Bind a
 * checker over your own "enabled" flag instead; the wiring is in docs/security-configuration.md.
 *
 * A checker that throws anything else is left to surface: an unrecognised refusal fails closed rather
 * than signing the user in.
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
