<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Lockout;

use Psr\Clock\ClockInterface;

/**
 * Generic lockout orchestration: counter increment with race-safe locking,
 * lockout trigger when threshold reached, auto-unlock window evaluation,
 * post-success reset. Subclass owns persistence (pessimistic row lock,
 * flush) and the rate-limit cleanup that pairs with manual unlock — both
 * are framework-specific (Doctrine ORM, plugin's `RateLimitGuardInterface`).
 */
abstract class AbstractLockoutManager
{
    public function __construct(
        protected LockoutPolicyInterface $policy,
        protected ClockInterface $clock,
    ) {
    }

    public function recordFailure(LockableUserInterface $user): void
    {
        if (! $this->policy->isEnabled()) {
            return;
        }

        // Pessimistic row lock on the user — without it, concurrent failed-login
        // requests would race the read-modify-write of failedLoginAttempts and
        // collapse multiple increments into one, letting an attacker exceed
        // maxAttempts before lockout engages. Subclass owns the lock semantics
        // (Doctrine beginTransaction / lock / refresh / commit).
        $this->withPessimisticLock($user, function () use ($user): void {
            $now = $this->clock->now();

            // If a previous lockout has already elapsed, start a fresh counter —
            // otherwise the next failure would immediately re-trip the lockout
            // at maxAttempts.
            $lockoutUntil = $user->getLockoutUntil();
            if ($user->getLockedAt() !== null && $lockoutUntil !== null && $lockoutUntil <= $now) {
                $user->setFailedLoginAttempts(0);
                $user->setLockedAt(null);
                $user->setLockoutUntil(null);
            }

            $attempts = $user->getFailedLoginAttempts() + 1;
            $user->setFailedLoginAttempts($attempts);
            $user->setLastFailedLoginAt($now);

            if ($attempts >= $this->policy->getMaxAttempts()) {
                $user->setLockedAt($now);
                $autoUnlockAfter = $this->policy->getAutoUnlockAfter();
                $user->setLockoutUntil(
                    $autoUnlockAfter === null ? null : $now->modify(sprintf('+%d seconds', $autoUnlockAfter)),
                );
            }
        });
    }

    public function recordSuccess(LockableUserInterface $user): void
    {
        if ($user->getFailedLoginAttempts() === 0 && $user->getLockedAt() === null) {
            return;
        }

        $user->setFailedLoginAttempts(0);
        $user->setLastFailedLoginAt(null);
        $user->setLockedAt(null);
        $user->setLockoutUntil(null);

        $this->commit();
    }

    public function isLocked(LockableUserInterface $user): bool
    {
        if (! $this->policy->isEnabled()) {
            return false;
        }

        if ($user->getLockedAt() === null) {
            return false;
        }

        // Pure query — never mutates. An expired auto-unlock window reads as
        // "not locked"; the persistent cleanup happens in recordFailure /
        // recordSuccess / unlock.
        $until = $user->getLockoutUntil();
        if ($until !== null && $until <= $this->clock->now()) {
            return false;
        }

        return true;
    }

    public function unlock(LockableUserInterface $user): void
    {
        $user->setFailedLoginAttempts(0);
        $user->setLastFailedLoginAt(null);
        $user->setLockedAt(null);
        $user->setLockoutUntil(null);

        $this->commit();

        // Without clearing the rate-limit counter, an unlocked user would still
        // be blocked at HTTP layer until the rate-limit window expires — making
        // manual unlock effectively useless. Subclass knows which identifier(s)
        // (username, email, …) the rate-limit keys are tied to.
        $this->clearRateLimitForUser($user);
    }

    /**
     * Run $callback within a per-user pessimistic row lock so concurrent
     * failed-login requests serialise on the counter increment. Subclass
     * typically wraps Doctrine's beginTransaction + lock + refresh + flush
     * + commit (with rollback on exception).
     */
    abstract protected function withPessimisticLock(LockableUserInterface $user, \Closure $callback): void;

    /**
     * Persist the lockout-state changes made by the current operation.
     * Typically `$entityManager->flush()`.
     */
    abstract protected function commit(): void;

    /**
     * Reset rate-limit counters keyed by this user's login identifiers, so a
     * just-unlocked user can sign in immediately without waiting out the HTTP
     * rate-limit window. Sylius shop uses email-only; Sylius admin may use
     * username + email — the subclass owns that mapping.
     */
    abstract protected function clearRateLimitForUser(LockableUserInterface $user): void;
}
