<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

/**
 * Persisted passkey credential record contract. Your entity (e.g. `App\Entity\UserPasskeyCredential`)
 * implements this interface plus your own user-relationship accessors
 * (`getUser()` / `setUser()`). The bundle's WebAuthn verifier reads
 * `credentialId` and `credentialSource` from a record implementing this
 * contract; updates `lastUsedAt` after a successful assertion; reads `label`
 * for the user-facing passkey list.
 *
 * Persisted `credentialSource` is the array form of WebAuthn's `PublicKeyCredentialSource`
 * (use the bundle's `PasskeyWebauthnSerializer` to convert in/out of the
 * webauthn-lib object).
 */
interface PasskeyCredentialRecordInterface
{
    public function getId(): ?int;

    public function getCredentialId(): string;

    public function setCredentialId(string $credentialId): void;

    /**
     * @return array<string, mixed>
     */
    public function getCredentialSource(): array;

    /**
     * @param array<string, mixed> $credentialSource
     */
    public function setCredentialSource(array $credentialSource): void;

    public function getLabel(): string;

    public function setLabel(string $label): void;

    public function getCreatedAt(): \DateTimeImmutable;

    public function getLastUsedAt(): ?\DateTimeImmutable;

    public function setLastUsedAt(?\DateTimeImmutable $lastUsedAt): void;
}
