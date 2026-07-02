<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Settings\Defaults;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults\SettingsDefaultsBuilder;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(SettingsDefaultsBuilder::class)]
class SettingsDefaultsBuilderTest extends TestCase
{
    public function testBuildPopulatesPerScopeMaps(): void
    {
        $defaults = (new SettingsDefaultsBuilder())->build($this->inlineConfig());

        self::assertArrayHasKey(SettingsScope::CUSTOMER->value, $defaults);
        self::assertArrayHasKey(SettingsScope::ADMIN->value, $defaults);
        self::assertArrayHasKey(SettingsScope::GLOBAL->value, $defaults);
    }

    public function testBuildPrefixesFeatureKeysWithFeatureName(): void
    {
        $defaults = (new SettingsDefaultsBuilder())->build($this->inlineConfig());

        self::assertSame(8, $defaults[SettingsScope::CUSTOMER->value]['password_policy.min_length']);
        self::assertSame(12, $defaults[SettingsScope::ADMIN->value]['password_policy.min_length']);
        self::assertFalse($defaults[SettingsScope::CUSTOMER->value]['password_history.enabled']);
        self::assertSame('disabled', $defaults[SettingsScope::CUSTOMER->value]['two_factor_authentication.mode']);
    }

    public function testBuildPlacesGlobalOnlyKeysInGlobalScope(): void
    {
        $defaults = (new SettingsDefaultsBuilder())->build($this->inlineConfig());

        self::assertSame('TestIssuer', $defaults[SettingsScope::GLOBAL->value]['two_factor_authentication.issuer']);
        self::assertSame(60, $defaults[SettingsScope::GLOBAL->value]['two_factor_authentication.trusted_device.days']);
        self::assertNull($defaults[SettingsScope::GLOBAL->value]['passkey.rp_id']);
        self::assertFalse($defaults[SettingsScope::ADMIN->value]['ip_whitelist.enabled']);
        self::assertSame([], $defaults[SettingsScope::ADMIN->value]['ip_whitelist.global_cidrs']);
        self::assertFalse($defaults[SettingsScope::ADMIN->value]['ip_blacklist.enabled']);
        self::assertSame([], $defaults[SettingsScope::ADMIN->value]['ip_blacklist.global_cidrs']);
    }

    public function testBuildFlattensRateLimitActions(): void
    {
        $defaults = (new SettingsDefaultsBuilder())->build($this->inlineConfig());

        self::assertSame(5, $defaults[SettingsScope::CUSTOMER->value]['rate_limit.login.limit']);
        self::assertSame('15 minutes', $defaults[SettingsScope::CUSTOMER->value]['rate_limit.login.interval']);
        self::assertSame(3, $defaults[SettingsScope::ADMIN->value]['rate_limit.password_reset.limit']);
    }

    public function testBuildFlattensOauthProviders(): void
    {
        $defaults = (new SettingsDefaultsBuilder())->build($this->inlineConfig());

        self::assertFalse($defaults[SettingsScope::CUSTOMER->value]['oauth.google.enabled']);
        self::assertNull($defaults[SettingsScope::CUSTOMER->value]['oauth.google.client_id']);
        self::assertFalse($defaults[SettingsScope::CUSTOMER->value]['oauth.microsoft.enabled']);
        self::assertNull($defaults[SettingsScope::CUSTOMER->value]['oauth.microsoft.client_id']);
        self::assertSame('common', $defaults[SettingsScope::CUSTOMER->value]['oauth.microsoft.tenant']);
        self::assertSame('en_US', $defaults[SettingsScope::CUSTOMER->value]['oauth.default_locale']);
        self::assertSame([], $defaults[SettingsScope::CUSTOMER->value]['oauth.auto_register_allowed_email_domains']);
        self::assertSame('en_US', $defaults[SettingsScope::ADMIN->value]['oauth.default_locale']);
        self::assertSame([], $defaults[SettingsScope::ADMIN->value]['oauth.auto_register_allowed_email_domains']);
        self::assertFalse($defaults[SettingsScope::ADMIN->value]['oauth.microsoft.enabled']);
    }

    /**
     * @return array<string, mixed>
     */
    private function inlineConfig(): array
    {
        $perScopeFeature = static fn (array $extra = []): array => array_merge([
            'enabled' => false,
        ], $extra);

        return [
            'password_policy' => [
                'customer' => [
                    'min_length' => 8,
                    'max_length' => null,
                ],
                'admin' => [
                    'min_length' => 12,
                    'max_length' => null,
                ],
            ],
            'password_history' => [
                'customer' => $perScopeFeature([
                    'count' => 5,
                ]),
                'admin' => $perScopeFeature([
                    'count' => 10,
                ]),
            ],
            'password_expiration' => [
                'customer' => $perScopeFeature([
                    'days' => 90,
                ]),
                'admin' => $perScopeFeature([
                    'days' => 60,
                ]),
            ],
            'password_change_notification' => [
                'customer' => $perScopeFeature(),
                'admin' => $perScopeFeature(),
            ],
            'two_factor_authentication' => [
                'issuer' => 'TestIssuer',
                'customer' => [
                    'mode' => 'disabled',
                ],
                'admin' => [
                    'mode' => 'disabled',
                ],
                'recovery_codes' => [
                    'customer' => [
                        'enabled' => true,
                        'count' => 8,
                    ],
                    'admin' => [
                        'enabled' => true,
                        'count' => 8,
                    ],
                ],
                'trusted_device' => [
                    'enabled' => true,
                    'days' => 60,
                ],
            ],
            'magic_link' => [
                'customer' => $perScopeFeature([
                    'expiration_seconds' => 300,
                ]),
                'admin' => $perScopeFeature([
                    'expiration_seconds' => 300,
                ]),
            ],
            'passkey' => [
                'customer' => $perScopeFeature(),
                'admin' => $perScopeFeature(),
                'rp_id' => null,
                'rp_name' => null,
            ],
            'account_lockout' => [
                'customer' => $perScopeFeature([
                    'max_attempts' => 5,
                    'auto_unlock_after' => null,
                ]),
                'admin' => $perScopeFeature([
                    'max_attempts' => 3,
                    'auto_unlock_after' => null,
                ]),
            ],
            'rate_limit' => [
                'customer' => [
                    'login' => [
                        'limit' => 5,
                        'interval' => '15 minutes',
                    ],
                    'password_reset' => [
                        'limit' => 5,
                        'interval' => '15 minutes',
                    ],
                ],
                'admin' => [
                    'login' => [
                        'limit' => 5,
                        'interval' => '15 minutes',
                    ],
                    'password_reset' => [
                        'limit' => 3,
                        'interval' => '15 minutes',
                    ],
                ],
            ],
            'session_management' => [
                'customer' => $perScopeFeature(),
                'admin' => $perScopeFeature(),
                'geoip_service' => null,
            ],
            'login_notifications' => [
                'customer' => $perScopeFeature(),
                'admin' => $perScopeFeature(),
            ],
            'password_login' => [
                'customer' => $perScopeFeature(),
                'admin' => $perScopeFeature(),
            ],
            'account_deletion' => [
                'customer' => $perScopeFeature([
                    'grace_period_days' => 30,
                ]),
            ],
            'oauth' => [
                'customer' => [
                    'default_locale' => 'en_US',
                    'auto_register_allowed_email_domains' => [],
                    'google' => [
                        'enabled' => false,
                        'client_id' => null,
                        'client_secret' => null,
                    ],
                    'apple' => [
                        'enabled' => false,
                        'client_id' => null,
                        'team_id' => null,
                        'key_id' => null,
                        'private_key_path' => null,
                    ],
                    'microsoft' => [
                        'enabled' => false,
                        'client_id' => null,
                        'client_secret' => null,
                        'tenant' => 'common',
                    ],
                ],
                'admin' => [
                    'default_locale' => 'en_US',
                    'auto_register_allowed_email_domains' => [],
                    'google' => [
                        'enabled' => false,
                        'client_id' => null,
                        'client_secret' => null,
                    ],
                    'apple' => [
                        'enabled' => false,
                        'client_id' => null,
                        'team_id' => null,
                        'key_id' => null,
                        'private_key_path' => null,
                    ],
                    'microsoft' => [
                        'enabled' => false,
                        'client_id' => null,
                        'client_secret' => null,
                        'tenant' => 'common',
                    ],
                ],
            ],
            'ip_whitelist' => [
                'enabled' => false,
            ],
            'ip_blacklist' => [
                'enabled' => false,
            ],
        ];
    }
}
