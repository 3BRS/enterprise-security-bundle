<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordHistory;

class PasswordSimilarityChecker implements PasswordSimilarityCheckerInterface
{
    public function isSimilar(string $a, string $b): bool
    {
        if ($a === '' || $b === '') {
            return false;
        }

        return str_contains($a, $b) || str_contains($b, $a);
    }
}
