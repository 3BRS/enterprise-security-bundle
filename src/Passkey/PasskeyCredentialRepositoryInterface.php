<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

/**
 * Repository contract for looking up persisted passkey credentials. The bundle's
 * `PasskeyAssertionVerifier` implementations look up a credential record by the
 * raw credential ID returned from the browser during a WebAuthn assertion
 * ceremony.
 *
 * Your concrete repository typically narrows the return type to your own
 * record entity via PHPDoc covariance (e.g. `@return ?App\Entity\UserPasskeyCredential`).
 */
interface PasskeyCredentialRepositoryInterface
{
    public function findOneByCredentialId(string $credentialId): ?PasskeyCredentialRecordInterface;
}
