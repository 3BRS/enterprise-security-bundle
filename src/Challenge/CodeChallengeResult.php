<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Challenge;

enum CodeChallengeResult
{
    case OK;
    case EXPIRED;
    case TOO_MANY_ATTEMPTS;
    case INVALID;
}
