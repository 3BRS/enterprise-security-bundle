<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;

class PasskeyValidatorFactory implements PasskeyValidatorFactoryInterface
{
    public function __construct(
        protected PasskeyCeremonyStepManagerFactoryInterface $ceremonyStepManagerFactory,
    ) {
    }

    public function createAttestationValidator(): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create(
            $this->ceremonyStepManagerFactory->createForCreationCeremony(),
        );
    }

    public function createAssertionValidator(): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create(
            $this->ceremonyStepManagerFactory->createForRequestCeremony(),
        );
    }
}
