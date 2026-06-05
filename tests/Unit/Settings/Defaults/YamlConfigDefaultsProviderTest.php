<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Settings\Defaults;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults\YamlConfigDefaultsProvider;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(YamlConfigDefaultsProvider::class)]
class YamlConfigDefaultsProviderTest extends TestCase
{
    public function testGetReturnsValueWhenPresent(): void
    {
        $provider = new YamlConfigDefaultsProvider([
            'customer' => [
                'password_policy.min_length' => 8,
            ],
            'admin' => [],
            'global' => [],
        ]);

        self::assertSame(8, $provider->get('password_policy.min_length', SettingsScope::CUSTOMER));
    }

    public function testGetReturnsNullWhenAbsent(): void
    {
        $provider = new YamlConfigDefaultsProvider([
            'customer' => [],
            'admin' => [],
            'global' => [],
        ]);

        self::assertNull($provider->get('does.not.exist', SettingsScope::CUSTOMER));
    }

    public function testAllReturnsRawMap(): void
    {
        $defaults = [
            'customer' => [
                'x' => 1,
            ],
            'admin' => [
                'y' => 2,
            ],
            'global' => [
                'z' => 3,
            ],
        ];

        $provider = new YamlConfigDefaultsProvider($defaults);

        self::assertSame($defaults, $provider->all());
    }
}
