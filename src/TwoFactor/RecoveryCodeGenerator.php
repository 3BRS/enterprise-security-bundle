<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

class RecoveryCodeGenerator implements RecoveryCodeGeneratorInterface
{
    public function generate(int $count): array
    {
        if ($count < 1) {
            throw new \InvalidArgumentException('Count must be at least 1.');
        }

        $codes = [];
        for ($i = 0; $i < $count; ++$i) {
            $codes[] = $this->generateSingle();
        }

        return $codes;
    }

    public function hash(string $plainCode): string
    {
        return hash('sha256', $this->normalize($plainCode));
    }

    protected function generateSingle(): string
    {
        $raw = bin2hex(random_bytes(8));

        return strtoupper(implode('-', str_split($raw, 4)));
    }

    protected function normalize(string $code): string
    {
        return strtoupper(str_replace([' ', '-'], '', $code));
    }
}
