<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\MagicLink;

interface MagicLinkRecordInterface
{
    public function getTokenHash(): string;

    public function setTokenHash(string $tokenHash): void;

    public function getExpiresAt(): \DateTimeImmutable;

    public function setExpiresAt(\DateTimeImmutable $expiresAt): void;

    public function getUsedAt(): ?\DateTimeImmutable;

    public function setUsedAt(?\DateTimeImmutable $usedAt): void;

    public function getCreatedAt(): \DateTimeImmutable;
}
