<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture;

use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

/**
 * A user that carries a password, as required by the flows that re-authenticate the account
 * (e.g. confirming an irreversible request with the current password).
 */
class TestPasswordUser extends TestUser implements PasswordAuthenticatedUserInterface
{
    /**
     * @param non-empty-string $identifier
     * @param list<string> $roles
     */
    public function __construct(
        string $identifier = 'test-user',
        array $roles = ['ROLE_USER'],
        protected string $password = 'hashed-password',
    ) {
        parent::__construct($identifier, $roles);
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }
}
