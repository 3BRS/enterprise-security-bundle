<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\PublicKeyCredentialRpEntity;

interface PasskeyRelyingPartyEntityFactoryInterface
{
    public function create(): PublicKeyCredentialRpEntity;

    public function getRpId(): string;
}
