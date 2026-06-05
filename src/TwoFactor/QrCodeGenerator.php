<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Endroid\QrCode\Builder\Builder;

class QrCodeGenerator implements QrCodeGeneratorInterface
{
    public function generateDataUri(string $data, int $size = 300): string
    {
        return (new Builder(data: $data, size: $size, margin: 10))->build()->getDataUri();
    }
}
