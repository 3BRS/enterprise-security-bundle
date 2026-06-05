<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\GeoIpLookupInterface;

/**
 * Generic session tracking orchestration: create one tracker row per
 * authenticated session, throttled activity touch, single + bulk revoke.
 * GeoIP resolution happens at create-time via the bundle's `GeoIpLookupInterface`.
 * Subclass owns the repository lookup, record factory, and Doctrine persistence
 * primitives (persist + flush + detach) — those are framework-coupled.
 */
abstract class AbstractSessionTracker
{
    protected const ACTIVITY_TOUCH_THROTTLE_SECONDS = 60;

    public function __construct(
        protected GeoIpLookupInterface $geoIpLookup,
        protected ClockInterface $clock,
    ) {
    }

    public function track(
        UserInterface $user,
        string $sessionId,
        ?string $userAgent,
        ?string $ipAddress,
    ): SessionRecordInterface {
        $existing = $this->findOneBySessionId($sessionId);
        if ($existing !== null) {
            return $existing;
        }

        $geo = $this->geoIpLookup->lookup($ipAddress);

        $session = $this->createNewRecord(
            $user,
            $sessionId,
            $userAgent,
            $ipAddress,
            $geo?->countryCode,
            $geo?->city,
        );

        try {
            $this->save($session);
        } catch (\Throwable $exception) {
            // Concurrent login with the same PHP session ID raced ahead. Subclass
            // narrows the conflict detection to its persistence layer (e.g.
            // Doctrine's UniqueConstraintViolationException); any other failure
            // is re-thrown. Detach our unflushed entity and return the persisted
            // one so the caller still gets a tracked session.
            if (! $this->isConcurrentInsertConflict($exception)) {
                throw $exception;
            }

            $this->discardUnflushed($session);
            $existing = $this->findOneBySessionId($sessionId);
            if ($existing !== null) {
                return $existing;
            }

            throw new \RuntimeException('Failed to persist session tracker row.', 0, $exception);
        }

        return $session;
    }

    public function touch(string $sessionId): void
    {
        $session = $this->findOneBySessionId($sessionId);
        if ($session === null || $session->isRevoked()) {
            return;
        }

        // Throttled — without this, every authenticated request would flush a
        // touch update, hammering the DB on busy admin pages.
        $now = $this->clock->now();
        $diff = $now->getTimestamp() - $session->getLastActivityAt()->getTimestamp();
        if ($diff < self::ACTIVITY_TOUCH_THROTTLE_SECONDS) {
            return;
        }

        $session->setLastActivityAt($now);
        $this->commit();
    }

    public function revoke(SessionRecordInterface $session): void
    {
        if ($session->isRevoked()) {
            return;
        }

        $session->setRevokedAt($this->clock->now());
        $this->commit();
    }

    public function revokeOthers(string $currentSessionId, UserInterface $user): void
    {
        $now = $this->clock->now();
        foreach ($this->findActiveForUser($user) as $session) {
            if ($session->getSessionId() === $currentSessionId) {
                continue;
            }
            $session->setRevokedAt($now);
        }
        $this->commit();
    }

    abstract protected function findOneBySessionId(string $sessionId): ?SessionRecordInterface;

    /**
     * @return iterable<SessionRecordInterface>
     */
    abstract protected function findActiveForUser(UserInterface $user): iterable;

    abstract protected function createNewRecord(
        UserInterface $user,
        string $sessionId,
        ?string $userAgent,
        ?string $ipAddress,
        ?string $country,
        ?string $city,
    ): SessionRecordInterface;

    /**
     * Persist a freshly created record (typically `$em->persist($record); $em->flush();`).
     */
    abstract protected function save(SessionRecordInterface $record): void;

    /**
     * Discard an unflushed record after a race-condition (typically `$em->detach($record);`).
     */
    abstract protected function discardUnflushed(SessionRecordInterface $record): void;

    /**
     * Persist mutations to an existing record (typically `$em->flush()`).
     */
    abstract protected function commit(): void;

    /**
     * Returns true when the exception thrown by `save()` is a unique-key
     * conflict on the session-ID column — the race-on-insert case the
     * tracker recovers from by re-reading the persisted row. Subclass
     * narrows to its persistence layer (e.g. Doctrine's
     * `UniqueConstraintViolationException`).
     */
    abstract protected function isConcurrentInsertConflict(\Throwable $exception): bool;
}
