<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\RateLimit;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

class RateLimitGuard implements RateLimitGuardInterface
{
    public function __construct(
        protected DynamicRateLimiterFactoryInterface $factory,
    ) {
    }

    public function isEnabled(string $group, string $action): bool
    {
        return $this->factory->isEnabled($group, $action);
    }

    public function consume(Request $request, string $group, string $action, ?string $userIdentifier = null): void
    {
        if (! $this->isEnabled($group, $action)) {
            return;
        }

        $key = $this->buildKey($request, $userIdentifier);
        $limit = $this->factory->consume($group, $action, $key);

        if (! $limit->isAccepted()) {
            throw new TooManyRequestsHttpException(
                $limit->getRetryAfter()->getTimestamp() - time(),
                'three_brs.rate_limit.too_many_requests',
            );
        }
    }

    public function reset(string $group, string $action, string $userIdentifier): void
    {
        if (! $this->isEnabled($group, $action)) {
            return;
        }

        $this->factory->reset($group, $action, strtolower($userIdentifier));
    }

    /**
     * When the route provides a username (login forms), key only on that — gives admin
     * unlock a deterministic key to reset. For routes without a username (register,
     * password reset, magic-link request), key on IP — anti-enumeration / anti-spam.
     */
    protected function buildKey(Request $request, ?string $userIdentifier): string
    {
        if ($userIdentifier !== null && $userIdentifier !== '') {
            return strtolower($userIdentifier);
        }

        return $request->getClientIp() ?? 'unknown';
    }
}
