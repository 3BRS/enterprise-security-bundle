<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * "Have I seen this device for this user before?" — the question a login-notification
 * flow asks before emailing the user about a new sign-in. Answering it and remembering
 * the answer has to be one step, otherwise two concurrent sign-ins from the same device
 * both read "unknown" and both send the mail.
 *
 * Subclass owns the repository lookup, the record factory and the persistence
 * primitives (persist + flush + detach) — those are framework-coupled, exactly as in
 * `AbstractSessionTracker`.
 */
abstract class AbstractNewDeviceDetector
{
    /**
     * Returns true when the (user, fingerprint) pair had not been seen before — and
     * remembers it, so the next call for the same pair returns false.
     */
    public function checkAndRemember(UserInterface $user, string $fingerprint): bool
    {
        if ($this->isKnownDevice($user, $fingerprint)) {
            return false;
        }

        $device = $this->createRecord($user, $fingerprint);

        try {
            $this->save($device);
        } catch (\Throwable $exception) {
            // A concurrent sign-in from the same device raced ahead and persisted the
            // (user, fingerprint) row first — the unique key on the table is what makes
            // that visible. Subclass narrows the conflict detection to its persistence
            // layer (e.g. Doctrine's `UniqueConstraintViolationException`); any other
            // failure is re-thrown. Reporting the device as already known is the point:
            // the other request is sending the "new device" notification, and a second
            // one would be a duplicate.
            if (! $this->isConcurrentInsertConflict($exception)) {
                throw $exception;
            }

            $this->discardUnflushed($device);

            return false;
        }

        return true;
    }

    abstract protected function isKnownDevice(UserInterface $user, string $fingerprint): bool;

    /**
     * Build the record — set both the user relationship and the fingerprint on it.
     * It is persisted by `save()`, not here.
     */
    abstract protected function createRecord(UserInterface $user, string $fingerprint): KnownDeviceRecordInterface;

    /**
     * Persist a freshly created record (typically `$em->persist($record); $em->flush();`).
     */
    abstract protected function save(KnownDeviceRecordInterface $record): void;

    /**
     * Discard an unflushed record after a race-condition (typically `$em->detach($record);`).
     */
    abstract protected function discardUnflushed(KnownDeviceRecordInterface $record): void;

    /**
     * Returns true when the exception thrown by `save()` is a unique-key conflict on the
     * (user, fingerprint) pair — the race-on-insert case this detector recovers from.
     * Subclass narrows to its persistence layer (e.g. Doctrine's
     * `UniqueConstraintViolationException`).
     */
    abstract protected function isConcurrentInsertConflict(\Throwable $exception): bool;
}
