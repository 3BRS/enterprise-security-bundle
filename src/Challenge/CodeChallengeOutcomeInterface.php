<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

interface CodeChallengeOutcomeInterface
{
    public function getResult(): CodeChallengeResult;

    /**
     * The state to persist after this verification: the attempt counter incremented, or
     * the challenge burned once it is spent (correct code) or exhausted (too many tries).
     */
    public function getNextState(): CodeChallengeStateInterface;
}
