<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings;

interface SettingsProviderInterface
{
    public function getBool(string $path, SettingsScope $scope): bool;

    public function getInt(string $path, SettingsScope $scope): int;

    public function getNullableInt(string $path, SettingsScope $scope): ?int;

    public function getString(string $path, SettingsScope $scope): string;

    public function get(string $path, SettingsScope $scope): mixed;

    public function refresh(): void;
}
