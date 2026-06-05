<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

interface QrCodeGeneratorInterface
{
    public function generateDataUri(string $data, int $size = 300): string;
}
