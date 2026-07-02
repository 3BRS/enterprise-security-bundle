<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

interface CodeChallengeStateInterface
{
    /**
     * Hash of the currently issued code, or null when no live challenge exists
     * (never issued, or already burned).
     */
    public function getHash(): ?string;

    /**
     * Unix timestamp at which the current code stops being valid, or null when no
     * live challenge exists.
     */
    public function getExpiresAt(): ?int;

    /**
     * Number of verification attempts already spent against the current code.
     */
    public function getAttempts(): int;
}
