<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

/**
 * Immutable snapshot of a one-time-code challenge. Deliberately transport-agnostic: the
 * integrator decides where it lives (a session array, a cache entry, …) and rebuilds it
 * before each {@see CodeChallengeValidatorInterface::verify()} call.
 */
class CodeChallengeState implements CodeChallengeStateInterface
{
    public function __construct(
        protected readonly ?string $hash,
        protected readonly ?int $expiresAt,
        protected readonly int $attempts = 0,
    ) {
    }

    /**
     * The spent/empty state: no live code. A later verify reports it as expired and the
     * issuer is free to hand out a fresh one.
     */
    public static function burned(): self
    {
        return new self(null, null, 0);
    }

    public function getHash(): ?string
    {
        return $this->hash;
    }

    public function getExpiresAt(): ?int
    {
        return $this->expiresAt;
    }

    public function getAttempts(): int
    {
        return $this->attempts;
    }
}
