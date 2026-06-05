<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Twig;

interface PasskeyExtensionInterface
{
    public function isEnabled(string $group): bool;
}
