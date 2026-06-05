<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordLoginControl;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;

/**
 * Blocks a password-credentials login attempt when the resolved user has the per-user
 * password-login toggle disabled. OAuth / passkey / magic-link flows are untouched because
 * their passports do not carry a `PasswordCredentials` badge.
 *
 * Subclass binds the listener to a single user type (Customer vs AdminUser) — Symfony's
 * security event dispatchers fire per-firewall, but the same listener subscribes to all of
 * them, so the user-type filter is the only safe per-firewall narrowing.
 */
abstract class AbstractPasswordLoginCheckListener implements EventSubscriberInterface
{
    public function __construct(
        protected PasswordLoginPreferenceRepositoryInterface $preferenceRepository,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        // Priority 256 runs the check before Symfony's CheckCredentialsListener (which
        // verifies the password hash) — we reject a disabled password login up front to
        // avoid leaking a timing side-channel on whether the password was correct. The user
        // is already resolved here (UserProviderListener runs earlier, at priority 1024).
        return [
            CheckPassportEvent::class => ['onCheckPassport', 256],
        ];
    }

    public function onCheckPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        if (! $passport->hasBadge(PasswordCredentials::class)) {
            return;
        }

        $user = $passport->getUser();
        if (! $this->isAcceptableUser($user)) {
            return;
        }

        // Feature gate lives behind an abstract hook so the bundle stays
        // settings-agnostic; the concrete binds it to the relevant scope toggle.
        // When the feature is off, existing per-user preferences are ignored.
        if (! $this->isFeatureEnabled()) {
            return;
        }

        if ($this->preferenceRepository->isPasswordLoginAllowedForUser($user)) {
            return;
        }

        throw new CustomUserMessageAuthenticationException($this->getErrorMessageKey());
    }

    abstract protected function isFeatureEnabled(): bool;

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    /**
     * Translation key thrown via CustomUserMessageAuthenticationException; rendered on the
     * login page by Symfony's authentication-utils + the firewall's `failure_path` template.
     */
    abstract protected function getErrorMessageKey(): string;
}
