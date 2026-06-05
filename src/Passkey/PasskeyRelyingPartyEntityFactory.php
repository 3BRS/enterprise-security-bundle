<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\PublicKeyCredentialRpEntity;

class PasskeyRelyingPartyEntityFactory implements PasskeyRelyingPartyEntityFactoryInterface
{
    public function __construct(
        protected string $rpId,
        protected string $rpName,
    ) {
    }

    public function create(): PublicKeyCredentialRpEntity
    {
        return PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId);
    }

    public function getRpId(): string
    {
        return $this->rpId;
    }
}
