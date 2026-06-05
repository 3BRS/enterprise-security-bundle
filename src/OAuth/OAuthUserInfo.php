<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

class OAuthUserInfo implements OAuthUserInfoInterface
{
    public function __construct(
        protected readonly string $provider,
        protected readonly string $providerUserId,
        protected readonly ?string $email,
        protected readonly ?string $firstName = null,
        protected readonly ?string $lastName = null,
        protected readonly ?bool $emailVerified = null,
    ) {
    }

    public function getProvider(): string
    {
        return $this->provider;
    }

    public function getProviderUserId(): string
    {
        return $this->providerUserId;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    public function isEmailVerified(): ?bool
    {
        return $this->emailVerified;
    }
}
