<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

interface SessionPasskeyOptionsStorageInterface
{
    public function store(string $key, string $serialized): void;

    public function consume(string $key): ?string;
}
