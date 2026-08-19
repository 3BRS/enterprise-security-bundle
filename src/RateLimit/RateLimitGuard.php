<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\RateLimit;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

class RateLimitGuard implements RateLimitGuardInterface
{
    /**
     * @param array<string, string> $ipCompanionActions maps a username-keyed action to a second
     *                                                  action counted per client address, e.g.
     *                                                  `['login' => 'login_ip']`. Empty by default,
     *                                                  which is exactly the previous behaviour —
     *                                                  no extra counter and no extra settings read.
     */
    public function __construct(
        protected DynamicRateLimiterFactoryInterface $factory,
        protected array $ipCompanionActions = [],
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
        $retryAfter = $limit->isAccepted() ? null : $limit->getRetryAfter()->getTimestamp();

        // Consumed even when the primary counter has already refused, so it keeps accruing in the
        // case it exists for: spraying never trips any single account's limit, so an address budget
        // that only counted accepted requests would never fill.
        $companionAction = $this->resolveIpCompanionAction($action, $userIdentifier);
        if ($companionAction !== null && $this->isEnabled($group, $companionAction)) {
            // Keyed with no identifier, so buildKey() falls to the client address — including any
            // override a subclass made there, which is the point of routing through it.
            $companionLimit = $this->factory->consume($group, $companionAction, $this->buildKey($request, null));
            if (! $companionLimit->isAccepted()) {
                $companionRetryAfter = $companionLimit->getRetryAfter()->getTimestamp();
                $retryAfter = $retryAfter === null ? $companionRetryAfter : max($retryAfter, $companionRetryAfter);
            }
        }

        if ($retryAfter !== null) {
            throw new TooManyRequestsHttpException(
                $retryAfter - time(),
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
     * The companion counter only makes sense when the primary one is keyed on a username. Without
     * an identifier the primary is already keyed on the address, and counting the same request
     * twice would just halve the effective limit.
     */
    protected function resolveIpCompanionAction(string $action, ?string $userIdentifier): ?string
    {
        if ($userIdentifier === null || $userIdentifier === '') {
            return null;
        }

        return $this->ipCompanionActions[$action] ?? null;
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
