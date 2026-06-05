<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use OTPHP\TOTP;

class TotpSecretGenerator implements TotpSecretGeneratorInterface
{
    public function generateSecret(): string
    {
        return TOTP::generate()->getSecret();
    }

    public function buildProvisioningUri(string $secret, string $username, string $issuer): string
    {
        if ($secret === '' || $username === '' || $issuer === '') {
            throw new \InvalidArgumentException('Secret, username and issuer must be non-empty.');
        }

        $totp = TOTP::createFromSecret($secret);
        $totp->setLabel($username);
        $totp->setIssuer($issuer);

        return $totp->getProvisioningUri();
    }

    public function verifyCode(string $secret, string $code): bool
    {
        if ($secret === '' || $code === '') {
            return false;
        }

        return TOTP::createFromSecret($secret)->verify($code);
    }
}
