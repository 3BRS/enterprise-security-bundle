<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordLoginControl;

/**
 * Per-user record toggling whether the user may sign in with username/email + password.
 * Absence of a record for a given user means "allowed" (preserves vanilla Symfony login
 * behavior for users created before the feature was enabled).
 */
interface PasswordLoginPreferenceInterface
{
    public function getId(): ?int;

    public function isPasswordLoginAllowed(): bool;

    public function setPasswordLoginAllowed(bool $allowed): void;
}
