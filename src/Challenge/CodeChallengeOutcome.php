<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

class CodeChallengeOutcome implements CodeChallengeOutcomeInterface
{
    public function __construct(
        protected readonly CodeChallengeResult $result,
        protected readonly CodeChallengeStateInterface $nextState,
    ) {
    }

    public function getResult(): CodeChallengeResult
    {
        return $this->result;
    }

    public function getNextState(): CodeChallengeStateInterface
    {
        return $this->nextState;
    }
}
