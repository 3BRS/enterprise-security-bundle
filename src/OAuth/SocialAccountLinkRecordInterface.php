<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface SocialAccountLinkRecordInterface
{
    public function getProvider(): string;

    public function setProvider(string $provider): void;

    public function getProviderUserId(): string;

    public function setProviderUserId(string $providerUserId): void;

    public function getEmail(): ?string;

    public function setEmail(?string $email): void;

    public function getLinkedAt(): \DateTimeImmutable;

    public function getLastUsedAt(): ?\DateTimeImmutable;

    public function setLastUsedAt(?\DateTimeImmutable $lastUsedAt): void;
}
