<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

class PasskeyCeremonyStepManagerFactory implements PasskeyCeremonyStepManagerFactoryInterface
{
    public function __construct(
        protected string $rpId,
    ) {
    }

    public function createForCreationCeremony(): CeremonyStepManager
    {
        return $this->buildFactory()->creationCeremony();
    }

    public function createForRequestCeremony(): CeremonyStepManager
    {
        return $this->buildFactory()->requestCeremony();
    }

    protected function buildFactory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setSecuredRelyingPartyId([$this->rpId]);

        return $factory;
    }
}
