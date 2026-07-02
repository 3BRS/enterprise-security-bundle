<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

interface CodeChallengeValidatorInterface
{
    /**
     * Verifies a submitted proof against the stored challenge state, enforcing — in this
     * order — expiry, a guess limit and single-use, with a constant-time comparison of the
     * proof. Returns the verdict together with the next state the caller must persist.
     *
     * Pure: it never reads or writes the session (or any other store) and never mutates the
     * passed state — that keeps the security rules identical for every integrator, so each
     * one no longer re-implements them. Because the caller owns persistence, it is also the
     * caller's job to serialise concurrent verifies for the same state (e.g. session locking)
     * so the attempt counter cannot be bypassed by parallel requests.
     *
     * @param string|null $submittedHash hash of the submitted code, computed with the same
     *                                    algorithm used to build the stored hash; null when
     *                                    nothing (or an empty value) was submitted
     * @param int         $maxAttempts   guesses allowed before the challenge is burned; >= 1
     */
    public function verify(
        CodeChallengeStateInterface $state,
        ?string $submittedHash,
        int $maxAttempts,
    ): CodeChallengeOutcomeInterface;
}
