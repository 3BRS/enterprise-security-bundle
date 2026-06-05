<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\Request;
use TheNetworg\OAuth2\Client\Provider\Azure;
use TheNetworg\OAuth2\Client\Provider\AzureResourceOwner;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class MicrosoftOAuthProvider implements MicrosoftOAuthProviderInterface
{
    public const NAME = 'microsoft';

    public function __construct(
        protected SettingsProviderInterface $settings,
        protected ?string $customerClientId,
        protected ?string $customerClientSecret,
        protected ?string $customerTenant,
        protected ?string $adminClientId,
        protected ?string $adminClientSecret,
        protected ?string $adminTenant,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function isEnabledForCustomer(): bool
    {
        return $this->settings->getBool('oauth.microsoft.enabled', SettingsScope::CUSTOMER) &&
            $this->customerClientId !== null && $this->customerClientId !== '' &&
            $this->customerClientSecret !== null && $this->customerClientSecret !== '' &&
            $this->customerTenant !== null;
    }

    public function isEnabledForAdmin(): bool
    {
        return $this->settings->getBool('oauth.microsoft.enabled', SettingsScope::ADMIN) &&
            $this->adminClientId !== null && $this->adminClientId !== '' &&
            $this->adminClientSecret !== null && $this->adminClientSecret !== '' &&
            $this->adminTenant !== null;
    }

    public function getAuthorizationUrl(string $redirectUri, string $state, string $group): string
    {
        $this->assertGroup($group);
        $client = $this->buildClient($group, $redirectUri);

        return $client->getAuthorizationUrl([
            'scope' => ['openid', 'profile', 'email'],
            'state' => $state,
            'prompt' => 'select_account',
        ]);
    }

    public function fetchUserInfo(Request $request, string $redirectUri, string $expectedState, string $group): OAuthUserInfoInterface
    {
        $this->assertGroup($group);

        $state = (string) $request->query->get('state');
        if ($state === '' || ! hash_equals($expectedState, $state)) {
            throw new OAuthProviderException('Invalid OAuth state parameter.');
        }

        $code = (string) $request->query->get('code');
        if ($code === '') {
            throw new OAuthProviderException('Missing authorization code in Microsoft callback.');
        }

        $client = $this->buildClient($group, $redirectUri);

        try {
            /** @var AccessToken $token */
            $token = $client->getAccessToken('authorization_code', [
                'code' => $code,
            ]);
            /** @var AzureResourceOwner $resourceOwner */
            $resourceOwner = $client->getResourceOwner($token);
        } catch (\Throwable $exception) {
            throw new OAuthProviderException('Failed to fetch Microsoft user info: ' . $exception->getMessage(), 0, $exception);
        }

        return $this->buildUserInfo($resourceOwner->toArray());
    }

    /**
     * Maps parsed ID token (JWT) claims to OAuthUserInfo. Microsoft has a non-trivial email
     * resolution unique to this provider (Google/Apple use a single claim), so the mapping is
     * extracted into its own method to keep it unit-testable without HTTP-roundtripping the
     * Azure SDK.
     *
     * - Prefer the `email` claim (OIDC standard).
     * - Fall back to `upn` only when it looks like a real email — personal Microsoft accounts
     *   federated into a work/school tenant get a non-routable
     *   `<original>#EXT#@<tenant>.onmicrosoft.com` form, which we skip.
     * - `email_verified` is left null because Microsoft does not emit a standard claim for it
     *   on personal accounts, and AutoRegistrationPolicy treats null as "unknown" (not "false").
     *
     * @param array<string, mixed> $claims
     *
     * @internal Exposed for unit testing; production callers go through fetchUserInfo().
     */
    public function buildUserInfo(array $claims): OAuthUserInfoInterface
    {
        $email = $this->stringClaim($claims, 'email');
        if ($email === null) {
            $upn = $this->stringClaim($claims, 'upn');
            if ($upn !== null && ! str_contains($upn, '#EXT#')) {
                $email = $upn;
            }
        }

        return new OAuthUserInfo(
            self::NAME,
            $this->stringClaim($claims, 'oid') ?? '',
            $email,
            $this->stringClaim($claims, 'given_name'),
            $this->stringClaim($claims, 'family_name'),
            null,
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function stringClaim(array $claims, string $key): ?string
    {
        if (! isset($claims[$key]) || ! is_string($claims[$key])) {
            return null;
        }

        return $claims[$key] !== '' ? $claims[$key] : null;
    }

    protected function assertGroup(string $group): void
    {
        if (! in_array($group, ['customer', 'admin'], true)) {
            throw new OAuthProviderException('Group must be "customer" or "admin".');
        }
    }

    protected function buildClient(string $group, string $redirectUri): Azure
    {
        if ($group === 'customer') {
            if (! $this->isEnabledForCustomer()) {
                throw new OAuthProviderException('Microsoft OAuth is not enabled for customer.');
            }

            return $this->createAzureClient(
                (string) $this->customerClientId,
                (string) $this->customerClientSecret,
                (string) $this->customerTenant,
                $redirectUri,
            );
        }

        if (! $this->isEnabledForAdmin()) {
            throw new OAuthProviderException('Microsoft OAuth is not enabled for admin.');
        }

        return $this->createAzureClient(
            (string) $this->adminClientId,
            (string) $this->adminClientSecret,
            (string) $this->adminTenant,
            $redirectUri,
        );
    }

    protected function createAzureClient(string $clientId, string $clientSecret, string $tenant, string $redirectUri): Azure
    {
        return new Azure([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
            'tenant' => $tenant,
            'defaultEndPointVersion' => Azure::ENDPOINT_VERSION_2_0,
        ]);
    }
}
