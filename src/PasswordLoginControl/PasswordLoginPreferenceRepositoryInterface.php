<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordLoginControl;

use Symfony\Component\Security\Core\User\UserInterface;

interface PasswordLoginPreferenceRepositoryInterface
{
    /**
     * Returns true if the user may sign in with username/email + password. When no record
     * exists for the user, the default is true (= unchanged vanilla behavior).
     */
    public function isPasswordLoginAllowedForUser(UserInterface $user): bool;
}
