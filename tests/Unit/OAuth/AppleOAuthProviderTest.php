<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\AppleOAuthProvider;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(AppleOAuthProvider::class)]
class AppleOAuthProviderTest extends TestCase
{
    public function testGetName(): void
    {
        self::assertSame('apple', $this->provider()->getName());
    }

    public function testIsEnabledForCustomerRequiresAllFields(): void
    {
        self::assertTrue($this->provider(customerEnabled: true)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: false)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerTeamId: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerTeamId: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerKeyId: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerKeyId: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerPrivateKeyPath: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerPrivateKeyPath: '')->isEnabledForCustomer());
    }

    public function testIsEnabledForAdminRequiresAllFields(): void
    {
        self::assertTrue($this->provider(adminEnabled: true)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: false)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminTeamId: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminTeamId: '')->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminKeyId: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminKeyId: '')->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminPrivateKeyPath: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminPrivateKeyPath: '')->isEnabledForAdmin());
    }

    public function testFetchUserInfoRejectsInvalidGroup(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([], [
            'state' => 's',
            'code' => 'c',
        ]);

        $this->expectException(OAuthProviderException::class);
        $provider->fetchUserInfo($request, 'https://example.com/cb', 's', 'invalid');
    }

    public function testFetchUserInfoRejectsMismatchedState(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([], [
            'state' => 'wrong',
            'code' => 'c',
        ]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('Invalid OAuth state');
        $provider->fetchUserInfo($request, 'https://example.com/cb', 'expected', 'customer');
    }

    public function testFetchUserInfoRejectsMissingCode(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([], [
            'state' => 's',
        ]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('Missing authorization code');
        $provider->fetchUserInfo($request, 'https://example.com/cb', 's', 'customer');
    }

    public function testFetchUserInfoReadsStateAndCodeFromPostBody(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([], [
            'state' => 'wrong',
            'code' => 'c',
        ]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('Invalid OAuth state');
        $provider->fetchUserInfo($request, 'https://example.com/cb', 'expected', 'customer');
    }

    private function provider(
        bool $customerEnabled = true,
        ?string $customerClientId = 'cid',
        ?string $customerTeamId = 'tid',
        ?string $customerKeyId = 'kid',
        ?string $customerPrivateKeyPath = '/tmp/k.p8',
        bool $adminEnabled = true,
        ?string $adminClientId = 'acid',
        ?string $adminTeamId = 'atid',
        ?string $adminKeyId = 'akid',
        ?string $adminPrivateKeyPath = '/tmp/ak.p8',
    ): AppleOAuthProvider {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturnCallback(
            static fn (string $path, SettingsScope $scope): bool => match ($scope) {
                SettingsScope::CUSTOMER => $customerEnabled,
                SettingsScope::ADMIN => $adminEnabled,
                default => false,
            },
        );

        return new AppleOAuthProvider(
            $settings,
            $customerClientId,
            $customerTeamId,
            $customerKeyId,
            $customerPrivateKeyPath,
            $adminClientId,
            $adminTeamId,
            $adminKeyId,
            $adminPrivateKeyPath,
        );
    }
}
