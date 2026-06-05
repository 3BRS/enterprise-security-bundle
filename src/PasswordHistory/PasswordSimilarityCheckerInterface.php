<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordHistory;

interface PasswordSimilarityCheckerInterface
{
    /**
     * Two passwords are considered similar when one contains the other as a
     * substring (covers prefix/suffix growth such as "1234" → "12345"). Exact
     * matches return true (a string always contains itself).
     */
    public function isSimilar(string $a, string $b): bool;
}
