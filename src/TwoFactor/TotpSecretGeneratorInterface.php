<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

interface TotpSecretGeneratorInterface
{
    public function generateSecret(): string;

    public function buildProvisioningUri(string $secret, string $username, string $issuer): string;

    public function verifyCode(string $secret, string $code): bool;
}
