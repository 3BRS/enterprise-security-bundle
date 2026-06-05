<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults;

use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

interface SettingsDefaultsProviderInterface
{
    public function get(string $path, SettingsScope $scope): mixed;

    /**
     * @return array<string, array<string, mixed>>  scope.value => path.value => default
     */
    public function all(): array;
}
