<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings;

interface SettingsWriterInterface
{
    public function set(string $path, SettingsScope $scope, mixed $value): void;

    /**
     * @param array<string, mixed> $values path => value
     */
    public function setMany(SettingsScope $scope, array $values): void;

    public function flush(): void;
}
