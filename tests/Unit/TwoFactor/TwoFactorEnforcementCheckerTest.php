<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Settings\PolicyFactoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorAuthAdminUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorAuthShopUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorEnforcementChecker;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TwoFactorMode;

#[CoversClass(TwoFactorEnforcementChecker::class)]
class TwoFactorEnforcementCheckerTest extends TestCase
{
    public function testShopUserNotEnforcedWhenModeIsDisabled(): void
    {
        $checker = $this->createChecker(TwoFactorMode::DISABLED, TwoFactorMode::ENFORCED);

        self::assertFalse($checker->shouldEnforceForShopUser($this->shopUser(twoFactorEnabled: false)));
    }

    public function testShopUserNotEnforcedWhenModeIsAllowed(): void
    {
        $checker = $this->createChecker(TwoFactorMode::ALLOWED, TwoFactorMode::ENFORCED);

        self::assertFalse($checker->shouldEnforceForShopUser($this->shopUser(twoFactorEnabled: false)));
    }

    public function testShopUserEnforcedWhenModeIsEnforcedAndNotYetEnabled(): void
    {
        $checker = $this->createChecker(TwoFactorMode::ENFORCED, TwoFactorMode::DISABLED);

        self::assertTrue($checker->shouldEnforceForShopUser($this->shopUser(twoFactorEnabled: false)));
    }

    public function testShopUserNotEnforcedWhenAlreadyEnabled(): void
    {
        $checker = $this->createChecker(TwoFactorMode::ENFORCED, TwoFactorMode::DISABLED);

        self::assertFalse($checker->shouldEnforceForShopUser($this->shopUser(twoFactorEnabled: true)));
    }

    public function testAdminUserEnforcedWhenModeIsEnforcedAndNotYetEnabled(): void
    {
        $checker = $this->createChecker(TwoFactorMode::DISABLED, TwoFactorMode::ENFORCED);

        self::assertTrue($checker->shouldEnforceForAdminUser($this->adminUser(twoFactorEnabled: false)));
    }

    public function testAdminUserNotEnforcedWhenAlreadyEnabled(): void
    {
        $checker = $this->createChecker(TwoFactorMode::DISABLED, TwoFactorMode::ENFORCED);

        self::assertFalse($checker->shouldEnforceForAdminUser($this->adminUser(twoFactorEnabled: true)));
    }

    public function testAdminAndCustomerModesAreIndependent(): void
    {
        $checker = $this->createChecker(TwoFactorMode::DISABLED, TwoFactorMode::ENFORCED);

        self::assertFalse($checker->shouldEnforceForShopUser($this->shopUser(twoFactorEnabled: false)));
        self::assertTrue($checker->shouldEnforceForAdminUser($this->adminUser(twoFactorEnabled: false)));
    }

    private function createChecker(TwoFactorMode $customer, TwoFactorMode $admin): TwoFactorEnforcementChecker
    {
        $factory = $this->createStub(PolicyFactoryInterface::class);
        $factory->method('twoFactorMode')->willReturnCallback(static fn (SettingsScope $scope) => $scope === SettingsScope::ADMIN ? $admin : $customer);

        return new TwoFactorEnforcementChecker($factory);
    }

    private function shopUser(bool $twoFactorEnabled): TwoFactorAuthShopUserInterface
    {
        $user = $this->createStub(TwoFactorAuthShopUserInterface::class);
        $user->method('isTwoFactorEnabled')->willReturn($twoFactorEnabled);

        return $user;
    }

    private function adminUser(bool $twoFactorEnabled): TwoFactorAuthAdminUserInterface
    {
        $user = $this->createStub(TwoFactorAuthAdminUserInterface::class);
        $user->method('isTwoFactorEnabled')->willReturn($twoFactorEnabled);

        return $user;
    }
}
