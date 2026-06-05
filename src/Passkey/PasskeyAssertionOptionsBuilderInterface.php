<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Webauthn\PublicKeyCredentialRequestOptions;

interface PasskeyAssertionOptionsBuilderInterface
{
    public function build(): PublicKeyCredentialRequestOptions;
}
