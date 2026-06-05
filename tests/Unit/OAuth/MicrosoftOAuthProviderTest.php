<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\MicrosoftOAuthProvider;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

#[CoversClass(MicrosoftOAuthProvider::class)]
class MicrosoftOAuthProviderTest extends TestCase
{
    public function testGetName(): void
    {
        $provider = $this->provider();

        self::assertSame('microsoft', $provider->getName());
    }

    public function testIsEnabledForCustomerRequiresAllFields(): void
    {
        self::assertTrue($this->provider(customerEnabled: true)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: false)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientId: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientSecret: null)->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerClientSecret: '')->isEnabledForCustomer());
        self::assertFalse($this->provider(customerEnabled: true, customerTenant: null)->isEnabledForCustomer());
    }

    public function testIsEnabledForAdminRequiresAllFields(): void
    {
        self::assertTrue($this->provider(adminEnabled: true)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: false)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientId: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientId: '')->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientSecret: null)->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminClientSecret: '')->isEnabledForAdmin());
        self::assertFalse($this->provider(adminEnabled: true, adminTenant: null)->isEnabledForAdmin());
    }

    // NOTE: We deliberately do NOT unit-test the happy-path of getAuthorizationUrl() for Microsoft.
    // The thenetworg/oauth2-azure SDK fetches OpenID Connect discovery metadata from a live Azure
    // endpoint before constructing the URL, which makes a true unit test (without network or a
    // GUID-shaped fake client_id that still hits Azure) impractical. Our wrapper only delegates
    // — assertGroup() + isEnabledFor*() routing are still covered by the reject/disabled tests
    // below, and the SDK itself owns the URL composition contract.

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

    public function testBuildUserInfoPrefersEmailClaim(): void
    {
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-1',
            'email' => 'alice@example.com',
            'upn' => 'alice@tenant.onmicrosoft.com',
            'given_name' => 'Alice',
            'family_name' => 'Cooper',
        ]);

        self::assertSame('microsoft', $info->getProvider());
        self::assertSame('oid-1', $info->getProviderUserId());
        self::assertSame('alice@example.com', $info->getEmail());
        self::assertSame('Alice', $info->getFirstName());
        self::assertSame('Cooper', $info->getLastName());
        self::assertNull($info->isEmailVerified());
    }

    public function testBuildUserInfoFallsBackToUpnWhenEmailMissing(): void
    {
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-2',
            'upn' => 'bob@example.com',
        ]);

        self::assertSame('bob@example.com', $info->getEmail());
    }

    public function testBuildUserInfoFallsBackToUpnWhenEmailIsEmptyString(): void
    {
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-3',
            'email' => '',
            'upn' => 'carol@example.com',
        ]);

        self::assertSame('carol@example.com', $info->getEmail());
    }

    public function testBuildUserInfoSkipsGuestUpnContainingExtMarker(): void
    {
        // Personal Microsoft accounts federated into a work/school tenant get a
        // non-routable `<original>#EXT#@<tenant>.onmicrosoft.com` upn — we must NOT
        // treat that as a real email.
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-4',
            'upn' => 'dave_gmail.com#EXT#@tenant.onmicrosoft.com',
        ]);

        self::assertNull($info->getEmail());
    }

    public function testBuildUserInfoReturnsNullForMissingNameClaims(): void
    {
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-5',
            'email' => 'erin@example.com',
        ]);

        self::assertNull($info->getFirstName());
        self::assertNull($info->getLastName());
    }

    public function testBuildUserInfoIgnoresNonStringClaimValues(): void
    {
        // Hardens against malformed JWTs that put numbers or arrays where strings are expected.
        $info = $this->provider()->buildUserInfo([
            'oid' => 'oid-6',
            'email' => 123,
            'upn' => ['unexpected'],
            'given_name' => false,
            'family_name' => null,
        ]);

        self::assertNull($info->getEmail());
        self::assertNull($info->getFirstName());
        self::assertNull($info->getLastName());
    }

    public function testBuildUserInfoReturnsEmptyIdWhenOidMissing(): void
    {
        // Defensive: in practice every Microsoft id_token includes `oid`, but the upstream type
        // is mixed and OAuthUserInfo requires a string id.
        $info = $this->provider()->buildUserInfo([]);

        self::assertSame('', $info->getProviderUserId());
    }

    private function provider(
        bool $customerEnabled = true,
        ?string $customerClientId = 'cid',
        ?string $customerClientSecret = 'sec',
        ?string $customerTenant = 'common',
        bool $adminEnabled = true,
        ?string $adminClientId = 'acid',
        ?string $adminClientSecret = 'asec',
        ?string $adminTenant = 'common',
    ): MicrosoftOAuthProvider {
        $settings = $this->createStub(SettingsProviderInterface::class);
        $settings->method('getBool')->willReturnCallback(
            static fn (string $path, SettingsScope $scope): bool => match ($scope) {
                SettingsScope::CUSTOMER => $customerEnabled,
                SettingsScope::ADMIN => $adminEnabled,
                default => false,
            },
        );

        return new MicrosoftOAuthProvider(
            $settings,
            $customerClientId,
            $customerClientSecret,
            $customerTenant,
            $adminClientId,
            $adminClientSecret,
            $adminTenant,
        );
    }
}
