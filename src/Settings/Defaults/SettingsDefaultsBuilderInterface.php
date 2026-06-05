<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults;

interface SettingsDefaultsBuilderInterface
{
    /**
     * Convert processed Configuration tree into flat per-scope path map.
     *
     * @param array<string, mixed> $processedConfig output of ProcessConfiguration on the plugin Configuration tree
     *
     * @return array<string, array<string, mixed>> scope.value => path => value
     */
    public function build(array $processedConfig): array;
}
