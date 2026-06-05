<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\RateLimit;

use Symfony\Component\HttpFoundation\Request;

interface RateLimitGuardInterface
{
    /**
     * @throws \Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException
     */
    public function consume(Request $request, string $group, string $action, ?string $userIdentifier = null): void;

    public function isEnabled(string $group, string $action): bool;

    /**
     * Clears the rate-limit counter for the given (group, action, userIdentifier) tuple.
     * Used when an admin manually unlocks an account or when the lockout auto-expires —
     * without this, the user would still be blocked at HTTP layer until the rate-limit
     * window closes naturally, defeating the purpose of unlocking.
     */
    public function reset(string $group, string $action, string $userIdentifier): void;
}
