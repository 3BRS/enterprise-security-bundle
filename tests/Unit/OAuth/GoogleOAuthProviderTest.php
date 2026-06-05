<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\GoogleOAuthProvider;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(GoogleOAuthProvider::class)]
class GoogleOAuthProviderTest extends TestCase
{
    public function testGetName(): void
    {
        $provider = $this->provider();

        self::assertSame('google', $provider->getName());
    }

    public function testIsEnabledForCustomerRequiresAllFields(): void
    {
        self::assertTrue($this->provider(customerEnabled: true)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: false)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientSecret: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientSecret: '')->isEnabledForCustomer());
    }

    public function testIsEnabledForAdminRequiresAllFields(): void
    {
        self::assertTrue($this->provider(adminEnabled: true)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: false)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientId: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientId: '')->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientSecret: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientSecret: '')->isEnabledForAdmin());
    }

    public function testGetAuthorizationUrlIncludesState(): void
    {
        $provider = $this->provider(customerEnabled: true);

        $url = $provider->getAuthorizationUrl('https://example.com/cb', 'state-123', 'customer');

        self::assertStringContainsString('accounts.google.com', $url);
        self::assertStringContainsString('state=state-123', $url);
        self::assertStringContainsString('client_id=cid', $url);
        self::assertStringContainsString('redirect_uri=' . rawurlencode('https://example.com/cb'), $url);
    }

    public function testGetAuthorizationUrlRejectsUnknownGroup(): void
    {
        $provider = $this->provider(customerEnabled: true);

        $this->expectException(OAuthProviderException::class);
        $provider->getAuthorizationUrl('https://example.com/cb', 'state', 'invalid');
    }

    public function testGetAuthorizationUrlFailsForDisabledGroup(): void
    {
        $provider = $this->provider(customerEnabled: false);

        $this->expectException(OAuthProviderException::class);
        $provider->getAuthorizationUrl('https://example.com/cb', 'state', 'customer');
    }

    public function testFetchUserInfoRejectsInvalidGroup(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([
            'state' => 's',
            'code' => 'c',
        ]);

        $this->expectException(OAuthProviderException::class);
        $provider->fetchUserInfo($request, 'https://example.com/cb', 's', 'invalid');
    }

    public function testFetchUserInfoRejectsMismatchedState(): void
    {
        $provider = $this->provider(customerEnabled: true);
        $request = new Request([
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
        $request = new Request([
            'state' => 's',
        ]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('Missing authorization code');
        $provider->fetchUserInfo($request, 'https://example.com/cb', 's', 'customer');
    }

    private function provider(
        bool $customerEnabled = true,
        ?string $customerClientId = 'cid',
        ?string $customerClientSecret = 'sec',
        bool $adminEnabled = true,
        ?string $adminClientId = 'acid',
        ?string $adminClientSecret = 'asec',
    ): GoogleOAuthProvider {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturnCallback(
            static fn (string $path, SettingsScope $scope): bool => match ($scope) {
                SettingsScope::CUSTOMER => $customerEnabled,
                SettingsScope::ADMIN => $adminEnabled,
                default => false,
            },
        );

        return new GoogleOAuthProvider(
            $settings,
            $customerClientId,
            $customerClientSecret,
            $adminClientId,
            $adminClientSecret,
        );
    }
}
