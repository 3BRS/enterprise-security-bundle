<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\CeremonyStep\CeremonyStepManager;

interface PasskeyCeremonyStepManagerFactoryInterface
{
    public function createForCreationCeremony(): CeremonyStepManager;

    public function createForRequestCeremony(): CeremonyStepManager;
}
