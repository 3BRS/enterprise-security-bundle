<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\PasswordExpiration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration\PasswordExpirationAdminUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration\PasswordExpirationChecker;
use ThreeBRS\EnterpriseSecurityBundle\PasswordExpiration\PasswordExpirationShopUserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(PasswordExpirationChecker::class)]
class PasswordExpirationCheckerTest extends TestCase
{
    public function testShopUserNotExpiredWhenDisabled(): void
    {
        $checker = $this->createChecker(customerEnabled: false);

        self::assertFalse($checker->isShopUserPasswordExpired($this->shopUser(passwordChangedAt: new \DateTimeImmutable('-999 days'))));
    }

    public function testShopUserExpiredWhenForcePasswordChangeIsTrue(): void
    {
        $checker = $this->createChecker();

        self::assertTrue($checker->isShopUserPasswordExpired($this->shopUser(forcePasswordChange: true)));
    }

    public function testShopUserExpiredWhenPasswordChangedAtIsNull(): void
    {
        $checker = $this->createChecker();

        self::assertTrue($checker->isShopUserPasswordExpired($this->shopUser(passwordChangedAt: null)));
    }

    public function testShopUserExpiredWhenPasswordOlderThanConfiguredDays(): void
    {
        $checker = $this->createChecker(customerDays: 30);

        self::assertTrue($checker->isShopUserPasswordExpired(
            $this->shopUser(passwordChangedAt: new \DateTimeImmutable('-31 days')),
        ));
    }

    public function testShopUserNotExpiredWhenPasswordChangedRecently(): void
    {
        $checker = $this->createChecker(customerDays: 30);

        self::assertFalse($checker->isShopUserPasswordExpired(
            $this->shopUser(passwordChangedAt: new \DateTimeImmutable('-10 days')),
        ));
    }

    public function testAdminUserNotExpiredWhenDisabled(): void
    {
        $checker = $this->createChecker(adminEnabled: false);

        self::assertFalse($checker->isAdminUserPasswordExpired($this->adminUser(passwordChangedAt: new \DateTimeImmutable('-999 days'))));
    }

    public function testAdminUserExpiredWhenForcePasswordChangeIsTrue(): void
    {
        $checker = $this->createChecker();

        self::assertTrue($checker->isAdminUserPasswordExpired($this->adminUser(forcePasswordChange: true)));
    }

    public function testAdminUserExpiredWhenPasswordChangedAtIsNull(): void
    {
        $checker = $this->createChecker();

        self::assertTrue($checker->isAdminUserPasswordExpired($this->adminUser(passwordChangedAt: null)));
    }

    public function testAdminUserExpiredWhenPasswordOlderThanConfiguredDays(): void
    {
        $checker = $this->createChecker(adminDays: 60);

        self::assertTrue($checker->isAdminUserPasswordExpired(
            $this->adminUser(passwordChangedAt: new \DateTimeImmutable('-61 days')),
        ));
    }

    public function testAdminUserNotExpiredWhenPasswordChangedRecently(): void
    {
        $checker = $this->createChecker(adminDays: 60);

        self::assertFalse($checker->isAdminUserPasswordExpired(
            $this->adminUser(passwordChangedAt: new \DateTimeImmutable('-30 days')),
        ));
    }

    public function testCustomerAndAdminHaveIndependentConfiguration(): void
    {
        $checker = $this->createChecker(customerEnabled: false, adminEnabled: true, adminDays: 60);

        self::assertFalse($checker->isShopUserPasswordExpired($this->shopUser(passwordChangedAt: new \DateTimeImmutable('-999 days'))));
        self::assertTrue($checker->isAdminUserPasswordExpired($this->adminUser(forcePasswordChange: true)));
    }

    private function createChecker(
        bool $customerEnabled = true,
        int $customerDays = 90,
        bool $adminEnabled = true,
        int $adminDays = 60,
    ): PasswordExpirationChecker {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturnCallback(static function (string $path, SettingsScope $scope) use ($customerEnabled, $adminEnabled): bool {
            if ($path === 'password_expiration.enabled' && $scope === SettingsScope::CUSTOMER) {
                return $customerEnabled;
            }
            if ($path === 'password_expiration.enabled' && $scope === SettingsScope::ADMIN) {
                return $adminEnabled;
            }

            return false;
        });
        $settings->method('getInt')->willReturnCallback(static function (string $path, SettingsScope $scope) use ($customerDays, $adminDays): int {
            if ($path === 'password_expiration.days' && $scope === SettingsScope::CUSTOMER) {
                return $customerDays;
            }
            if ($path === 'password_expiration.days' && $scope === SettingsScope::ADMIN) {
                return $adminDays;
            }

            return 0;
        });

        return new PasswordExpirationChecker($settings);
    }

    private function shopUser(
        bool $forcePasswordChange = false,
        ?\DateTimeImmutable $passwordChangedAt = null,
    ): PasswordExpirationShopUserInterface {
        $user = $this->createStub(PasswordExpirationShopUserInterface::class);
        $user->method('isForcePasswordChange')->willReturn($forcePasswordChange);
        $user->method('getPasswordChangedAt')->willReturn($passwordChangedAt);

        return $user;
    }

    private function adminUser(
        bool $forcePasswordChange = false,
        ?\DateTimeImmutable $passwordChangedAt = null,
    ): PasswordExpirationAdminUserInterface {
        $user = $this->createStub(PasswordExpirationAdminUserInterface::class);
        $user->method('isForcePasswordChange')->willReturn($forcePasswordChange);
        $user->method('getPasswordChangedAt')->willReturn($passwordChangedAt);

        return $user;
    }
}
