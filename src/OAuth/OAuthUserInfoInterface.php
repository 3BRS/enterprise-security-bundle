<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface OAuthUserInfoInterface
{
    public function getProvider(): string;

    public function getProviderUserId(): string;

    public function getEmail(): ?string;

    public function getFirstName(): ?string;

    public function getLastName(): ?string;

    public function isEmailVerified(): ?bool;
}
