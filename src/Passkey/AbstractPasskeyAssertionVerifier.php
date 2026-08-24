<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * The verify half of a WebAuthn assertion (passkey login): consume the ceremony options
 * stashed on the options endpoint, run the library check against the stored credential,
 * and write back what the check produced.
 *
 * Subclass owns only what is firewall-specific — which session key the options live
 * under, how a credential maps to a user, the result object, and the flush.
 */
abstract class AbstractPasskeyAssertionVerifier implements PasskeyAssertionVerifierInterface
{
    public function __construct(
        protected PasskeyCredentialRepositoryInterface $credentialRepository,
        protected SessionPasskeyOptionsStorageInterface $sessionStorage,
        protected PasskeyWebauthnSerializerInterface $serializer,
        protected PasskeyValidatorFactoryInterface $validatorFactory,
        protected ClockInterface $clock,
    ) {
    }

    public function verify(string $credentialResponseJson, string $host): PasskeyAssertionResultInterface
    {
        $serializedOptions = $this->sessionStorage->consume($this->getOptionsSessionKey());
        if ($serializedOptions === null) {
            throw new \RuntimeException('No passkey assertion ceremony in progress.');
        }

        $options = $this->serializer->deserialize($serializedOptions, PublicKeyCredentialRequestOptions::class);
        $publicKeyCredential = $this->serializer->deserialize($credentialResponseJson, PublicKeyCredential::class);

        $response = $publicKeyCredential->response;
        if (! $response instanceof AuthenticatorAssertionResponse) {
            throw new \RuntimeException('Expected AuthenticatorAssertionResponse from client.');
        }

        $stored = $this->credentialRepository->findOneByCredentialId($publicKeyCredential->rawId);
        if ($stored === null) {
            throw new \RuntimeException('Passkey credential not recognized.');
        }

        $source = $this->serializer->denormalize($stored->getCredentialSource(), PublicKeyCredentialSource::class);

        $updated = $this->validatorFactory->createAssertionValidator()->check(
            $source,
            $response,
            $options,
            $host,
            $source->userHandle,
        );

        $stored->setCredentialSource($this->serializer->normalize($updated));
        $stored->setLastUsedAt($this->clock->now());
        // The commit belongs here, not in the caller: persisting the updated signCount has
        // to be atomic with the check above, or two concurrent assertions replaying the
        // same authenticator response both pass before either one's counter lands.
        $this->commit();

        return $this->createResult($this->resolveUser($stored));
    }

    /**
     * The key the matching options builder stored the ceremony options under — one per
     * firewall, so a ceremony started on one cannot be completed on another.
     */
    abstract protected function getOptionsSessionKey(): string;

    /**
     * Resolve the credential's owner (typically `$credential->getUser()` on your entity).
     */
    abstract protected function resolveUser(PasskeyCredentialRecordInterface $credential): UserInterface;

    /**
     * Wrap the authenticated user in your result object — subclasses typically narrow the
     * return type to their own `PasskeyAssertionResultInterface` child.
     */
    abstract protected function createResult(UserInterface $user): PasskeyAssertionResultInterface;

    /**
     * Persist the mutations made to the credential record (typically `$em->flush()`).
     */
    abstract protected function commit(): void;
}
