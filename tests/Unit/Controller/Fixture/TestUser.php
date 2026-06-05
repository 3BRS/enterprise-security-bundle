<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture;

use Symfony\Component\Security\Core\User\UserInterface;

class TestUser implements UserInterface
{
    public function __construct(
        /**
         * @var non-empty-string
         */
        protected string $identifier = 'test-user',
        /**
         * @var list<string>
         */
        protected array $roles = ['ROLE_USER'],
    ) {
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
    }

    /**
     * @return non-empty-string
     */
    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }
}
