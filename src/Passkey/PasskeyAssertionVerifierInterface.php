<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

interface PasskeyAssertionVerifierInterface
{
    public function verify(string $credentialResponseJson, string $host): PasskeyAssertionResultInterface;
}
