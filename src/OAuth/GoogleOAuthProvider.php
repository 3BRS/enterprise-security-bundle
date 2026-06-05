<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class GoogleOAuthProvider implements GoogleOAuthProviderInterface
{
    public const NAME = 'google';

    public function __construct(
        protected SettingsProviderInterface $settings,
        protected ?string $customerClientId,
        protected ?string $customerClientSecret,
        protected ?string $adminClientId,
        protected ?string $adminClientSecret,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function isEnabledForCustomer(): bool
    {
        return $this->settings->getBool('oauth.google.enabled', SettingsScope::CUSTOMER) &&
            $this->customerClientId !== null && $this->customerClientId !== '' &&
            $this->customerClientSecret !== null && $this->customerClientSecret !== '';
    }

    public function isEnabledForAdmin(): bool
    {
        return $this->settings->getBool('oauth.google.enabled', SettingsScope::ADMIN) &&
            $this->adminClientId !== null && $this->adminClientId !== '' &&
            $this->adminClientSecret !== null && $this->adminClientSecret !== '';
    }

    public function getAuthorizationUrl(string $redirectUri, string $state, string $group): string
    {
        $this->assertGroup($group);
        $client = $this->buildClient($group, $redirectUri);

        return $client->getAuthorizationUrl([
            'scope' => ['email', 'profile'],
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
            throw new OAuthProviderException('Missing authorization code in Google callback.');
        }

        $client = $this->buildClient($group, $redirectUri);

        try {
            /** @var AccessToken $token */
            $token = $client->getAccessToken('authorization_code', [
                'code' => $code,
            ]);
            /** @var GoogleUser $resourceOwner */
            $resourceOwner = $client->getResourceOwner($token);
        } catch (\Throwable $exception) {
            throw new OAuthProviderException('Failed to fetch Google user info: ' . $exception->getMessage(), 0, $exception);
        }

        $raw = $resourceOwner->toArray();
        $emailVerified = isset($raw['email_verified']) ? (bool) $raw['email_verified'] : null;

        return new OAuthUserInfo(
            self::NAME,
            (string) $resourceOwner->getId(),
            $resourceOwner->getEmail(),
            $resourceOwner->getFirstName(),
            $resourceOwner->getLastName(),
            $emailVerified,
        );
    }

    protected function assertGroup(string $group): void
    {
        if (! in_array($group, ['customer', 'admin'], true)) {
            throw new OAuthProviderException('Group must be "customer" or "admin".');
        }
    }

    protected function buildClient(string $group, string $redirectUri): Google
    {
        if ($group === 'customer') {
            if (! $this->isEnabledForCustomer()) {
                throw new OAuthProviderException('Google OAuth is not enabled for customer.');
            }

            return new Google([
                'clientId' => (string) $this->customerClientId,
                'clientSecret' => (string) $this->customerClientSecret,
                'redirectUri' => $redirectUri,
            ]);
        }

        if (! $this->isEnabledForAdmin()) {
            throw new OAuthProviderException('Google OAuth is not enabled for admin.');
        }

        return new Google([
            'clientId' => (string) $this->adminClientId,
            'clientSecret' => (string) $this->adminClientSecret,
            'redirectUri' => $redirectUri,
        ]);
    }
}
