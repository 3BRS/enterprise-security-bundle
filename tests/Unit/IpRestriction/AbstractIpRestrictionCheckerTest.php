<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\IpRestriction;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\IpRestriction\AbstractIpRestrictionChecker;
use ThreeBRS\EnterpriseSecurityBundle\IpWhitelist\CidrMatcher;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(AbstractIpRestrictionChecker::class)]
class AbstractIpRestrictionCheckerTest extends TestCase
{
    public function testFeatureDisabledByDefault(): void
    {
        $checker = $this->createChecker(false, []);
        self::assertFalse($checker->isFeatureEnabled());
    }

    public function testFeatureEnabled(): void
    {
        $checker = $this->createChecker(true, []);
        self::assertTrue($checker->isFeatureEnabled());
    }

    public function testEmptyGlobalDoesNotMatch(): void
    {
        $checker = $this->createChecker(true, []);
        self::assertFalse($checker->matchesGlobal('1.2.3.4'));
    }

    public function testIpv4MatchesGlobalCidr(): void
    {
        $checker = $this->createChecker(true, ['10.0.0.0/8']);
        self::assertTrue($checker->matchesGlobal('10.5.6.7'));
        self::assertFalse($checker->matchesGlobal('11.0.0.1'));
    }

    public function testIpv6MatchesCidr(): void
    {
        $checker = $this->createChecker(true, ['2001:db8::/32']);
        self::assertTrue($checker->matchesGlobal('2001:db8::1'));
        self::assertFalse($checker->matchesGlobal('2002:db8::1'));
    }

    public function testEmptyIpNeverMatches(): void
    {
        $checker = $this->createChecker(true, ['10.0.0.0/8']);
        self::assertFalse($checker->matchesGlobal(''));
    }

    public function testGetGlobalCidrsFiltersNonStrings(): void
    {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('get')->willReturn(['10.0.0.0/8', '', 42, null, '192.168.1.1']);

        $checker = new class($settings, new CidrMatcher()) extends AbstractIpRestrictionChecker {
            protected function getSettingsKey(): string
            {
                return 'ip_restriction';
            }

            protected function getScope(): SettingsScope
            {
                return SettingsScope::ADMIN;
            }
        };

        self::assertSame(['10.0.0.0/8', '192.168.1.1'], $checker->getGlobalCidrs());
    }

    /**
     * @param list<string> $globalCidrs
     */
    private function createChecker(
        bool $enabled,
        array $globalCidrs,
        string $settingsKey = 'ip_restriction',
        SettingsScope $scope = SettingsScope::ADMIN,
    ): AbstractIpRestrictionChecker {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturnCallback(static function (string $path, SettingsScope $s) use ($enabled, $settingsKey, $scope): bool {
            if ($path === $settingsKey . '.enabled' && $s === $scope) {
                return $enabled;
            }

            return false;
        });
        $settings->method('get')->willReturnCallback(static function (string $path, SettingsScope $s) use ($globalCidrs, $settingsKey, $scope): mixed {
            if ($path === $settingsKey . '.global_cidrs' && $s === $scope) {
                return $globalCidrs;
            }

            return null;
        });

        return new class($settings, new CidrMatcher(), $settingsKey, $scope) extends AbstractIpRestrictionChecker {
            public function __construct(
                SettingsProviderInterface $settings,
                CidrMatcher $cidrMatcher,
                protected string $settingsKey,
                protected SettingsScope $scope,
            ) {
                parent::__construct($settings, $cidrMatcher);
            }

            protected function getSettingsKey(): string
            {
                return $this->settingsKey;
            }

            protected function getScope(): SettingsScope
            {
                return $this->scope;
            }
        };
    }
}
