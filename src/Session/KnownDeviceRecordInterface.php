<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Session;

/**
 * Persisted known-device record contract. Your entity (e.g. `App\Entity\UserKnownDevice`)
 * implements this interface plus your own user-relationship accessors
 * (`getUser()` / `setUser()`), and carries a unique key over the
 * (user, fingerprint) pair — `AbstractNewDeviceDetector` relies on the database
 * refusing a duplicate to settle a race between concurrent sign-ins.
 *
 * The fingerprint itself comes from the bundle's `SessionFingerprintGeneratorInterface`.
 */
interface KnownDeviceRecordInterface
{
    public function getId(): ?int;

    public function getFingerprint(): string;

    public function setFingerprint(string $fingerprint): void;

    public function getCreatedAt(): \DateTimeImmutable;
}
