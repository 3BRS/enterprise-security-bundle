<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults;

use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class SettingsDefaultsBuilder implements SettingsDefaultsBuilderInterface
{
    /**
     * @param array<string, mixed> $processedConfig
     *
     * @return array<string, array<string, mixed>>
     */
    public function build(array $processedConfig): array
    {
        $result = [
            SettingsScope::CUSTOMER->value => [],
            SettingsScope::ADMIN->value => [],
            SettingsScope::GLOBAL->value => [],
        ];

        foreach (['customer', 'admin'] as $scope) {
            $this->copyKeys($result[$scope], 'password_policy', $processedConfig['password_policy'][$scope]);
            $this->copyKeys($result[$scope], 'password_history', $processedConfig['password_history'][$scope]);
            $this->copyKeys($result[$scope], 'password_expiration', $processedConfig['password_expiration'][$scope]);
            $this->copyKeys($result[$scope], 'password_change_notification', $processedConfig['password_change_notification'][$scope]);

            $result[$scope]['two_factor_authentication.mode'] = $processedConfig['two_factor_authentication'][$scope]['mode'];
            $this->copyKeys($result[$scope], 'two_factor_authentication.recovery_codes', $processedConfig['two_factor_authentication']['recovery_codes'][$scope]);

            $this->copyKeys($result[$scope], 'magic_link', $processedConfig['magic_link'][$scope]);
            $this->copyKeys($result[$scope], 'passkey', $processedConfig['passkey'][$scope]);
            $this->copyKeys($result[$scope], 'account_lockout', $processedConfig['account_lockout'][$scope]);

            foreach ($processedConfig['rate_limit'][$scope] as $action => $settings) {
                foreach ($settings as $key => $value) {
                    $result[$scope]['rate_limit.' . $action . '.' . $key] = $value;
                }
            }

            $this->copyKeys($result[$scope], 'session_management', $processedConfig['session_management'][$scope]);
            $this->copyKeys($result[$scope], 'login_notifications', $processedConfig['login_notifications'][$scope]);
            $this->copyKeys($result[$scope], 'password_login_control', $processedConfig['password_login_control'][$scope]);

            // Account deletion is intentionally customer-scoped only (admin self-deletion is out of scope).
            if (isset($processedConfig['account_deletion'][$scope])) {
                $this->copyKeys($result[$scope], 'account_deletion', $processedConfig['account_deletion'][$scope]);
            }

            foreach ($processedConfig['oauth'][$scope] as $key => $value) {
                if ($key === 'google' || $key === 'apple' || $key === 'microsoft') {
                    foreach ($value as $providerKey => $providerValue) {
                        $result[$scope]['oauth.' . $key . '.' . $providerKey] = $providerValue;
                    }

                    continue;
                }
                $result[$scope]['oauth.' . $key] = $value;
            }
        }

        $result[SettingsScope::GLOBAL->value]['two_factor_authentication.issuer'] = $processedConfig['two_factor_authentication']['issuer'];
        $this->copyKeys(
            $result[SettingsScope::GLOBAL->value],
            'two_factor_authentication.trusted_device',
            $processedConfig['two_factor_authentication']['trusted_device'],
        );
        $result[SettingsScope::GLOBAL->value]['passkey.rp_id'] = $processedConfig['passkey']['rp_id'];
        $result[SettingsScope::GLOBAL->value]['passkey.rp_name'] = $processedConfig['passkey']['rp_name'];
        $result[SettingsScope::GLOBAL->value]['passkey.skip_2fa_when_user_verified'] = $processedConfig['passkey']['skip_2fa_when_user_verified'];
        $result[SettingsScope::GLOBAL->value]['session_management.geoip_service'] = $processedConfig['session_management']['geoip_service'];
        $result[SettingsScope::ADMIN->value]['ip_whitelist.enabled'] = (bool) $processedConfig['ip_whitelist']['enabled'];
        $result[SettingsScope::ADMIN->value]['ip_whitelist.global_cidrs'] = [];
        $result[SettingsScope::ADMIN->value]['ip_blacklist.enabled'] = (bool) $processedConfig['ip_blacklist']['enabled'];
        $result[SettingsScope::ADMIN->value]['ip_blacklist.global_cidrs'] = [];

        return $result;
    }

    /**
     * @param array<string, mixed> $target
     * @param array<string, mixed> $source
     */
    protected function copyKeys(array &$target, string $prefix, array $source): void
    {
        foreach ($source as $key => $value) {
            $target[$prefix . '.' . $key] = $value;
        }
    }
}
