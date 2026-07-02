<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

use Psr\Clock\ClockInterface;

/**
 * Shared verify half of a one-time-code challenge (e-mailed link code, 2FA code, …):
 * expiry + attempt limit + single-use + constant-time compare, so integrators only supply
 * how the code is generated, delivered and stored.
 *
 * @see CodeChallengeValidatorInterface for the contract and guarantees.
 */
class CodeChallengeValidator implements CodeChallengeValidatorInterface
{
    public function __construct(
        protected ClockInterface $clock,
    ) {
    }

    public function verify(
        CodeChallengeStateInterface $state,
        ?string $submittedHash,
        int $maxAttempts,
    ): CodeChallengeOutcomeInterface {
        $hash = $state->getHash();
        $expiresAt = $state->getExpiresAt();

        // Nothing live to check against: never issued, already burned, or past expiry.
        if ($hash === null || $expiresAt === null || $this->clock->now()->getTimestamp() >= $expiresAt) {
            return new CodeChallengeOutcome(CodeChallengeResult::EXPIRED, $state);
        }

        // Count this guess before comparing, so a wrong or empty submission still costs an attempt.
        $attempts = $state->getAttempts() + 1;

        // A short code is brute-forceable — once the guesses are exhausted, burn it.
        if ($attempts > $maxAttempts) {
            return new CodeChallengeOutcome(CodeChallengeResult::TOO_MANY_ATTEMPTS, CodeChallengeState::burned());
        }

        // hash_equals: constant-time, so a wrong code leaks no timing signal about the secret.
        if ($submittedHash === null || ! hash_equals($hash, $submittedHash)) {
            return new CodeChallengeOutcome(
                CodeChallengeResult::INVALID,
                new CodeChallengeState($hash, $expiresAt, $attempts),
            );
        }

        // Correct: single-use, so burn it to block replay.
        return new CodeChallengeOutcome(CodeChallengeResult::OK, CodeChallengeState::burned());
    }
}
