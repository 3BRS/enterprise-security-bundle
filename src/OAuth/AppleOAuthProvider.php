<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use League\OAuth2\Client\Provider\Apple;
use League\OAuth2\Client\Provider\AppleResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\Request;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class AppleOAuthProvider implements AppleOAuthProviderInterface, FormPostOAuthProviderInterface
{
    public const NAME = 'apple';

    public function __construct(
        protected SettingsProviderInterface $settings,
        protected ?string $customerClientId,
        protected ?string $customerTeamId,
        protected ?string $customerKeyId,
        protected ?string $customerPrivateKeyPath,
        protected ?string $adminClientId,
        protected ?string $adminTeamId,
        protected ?string $adminKeyId,
        protected ?string $adminPrivateKeyPath,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function isEnabledForCustomer(): bool
    {
        return $this->settings->getBool('oauth.apple.enabled', SettingsScope::CUSTOMER) &&
            $this->customerClientId !== null && $this->customerClientId !== '' &&
            $this->customerTeamId !== null && $this->customerTeamId !== '' &&
            $this->customerKeyId !== null && $this->customerKeyId !== '' &&
            $this->customerPrivateKeyPath !== null && $this->customerPrivateKeyPath !== '';
    }

    public function isEnabledForAdmin(): bool
    {
        return $this->settings->getBool('oauth.apple.enabled', SettingsScope::ADMIN) &&
            $this->adminClientId !== null && $this->adminClientId !== '' &&
            $this->adminTeamId !== null && $this->adminTeamId !== '' &&
            $this->adminKeyId !== null && $this->adminKeyId !== '' &&
            $this->adminPrivateKeyPath !== null && $this->adminPrivateKeyPath !== '';
    }

    public function getAuthorizationUrl(string $redirectUri, string $state, string $group): string
    {
        $this->assertGroup($group);
        $client = $this->buildClient($group, $redirectUri);

        return $client->getAuthorizationUrl([
            'scope' => ['name', 'email'],
            'response_mode' => 'form_post',
            'state' => $state,
        ]);
    }

    public function fetchUserInfo(Request $request, string $redirectUri, string $expectedState, string $group): OAuthUserInfoInterface
    {
        $this->assertGroup($group);

        $state = (string) $request->request->get('state', $request->query->get('state', ''));
        if ($state === '' || ! hash_equals($expectedState, $state)) {
            throw new OAuthProviderException('Invalid OAuth state parameter.');
        }

        $code = (string) $request->request->get('code', $request->query->get('code', ''));
        if ($code === '') {
            throw new OAuthProviderException('Missing authorization code in Apple callback.');
        }

        $client = $this->buildClient($group, $redirectUri);

        try {
            /** @var AccessToken $token */
            $token = $client->getAccessToken('authorization_code', [
                'code' => $code,
            ]);
            /** @var AppleResourceOwner $resourceOwner */
            $resourceOwner = $client->getResourceOwner($token);
        } catch (\Throwable $exception) {
            throw new OAuthProviderException('Failed to fetch Apple user info: ' . $exception->getMessage(), 0, $exception);
        }

        $firstName = $resourceOwner->getFirstName();
        $lastName = $resourceOwner->getLastName();

        $userParam = $request->request->get('user');
        if (is_string($userParam) && $userParam !== '') {
            $decoded = json_decode($userParam, true);
            if (is_array($decoded) && isset($decoded['name']) && is_array($decoded['name'])) {
                $firstName = $firstName ?? (isset($decoded['name']['firstName']) ? (string) $decoded['name']['firstName'] : null);
                $lastName = $lastName ?? (isset($decoded['name']['lastName']) ? (string) $decoded['name']['lastName'] : null);
            }
        }

        return new OAuthUserInfo(
            self::NAME,
            (string) $resourceOwner->getId(),
            $resourceOwner->getEmail(),
            $firstName,
            $lastName,
        );
    }

    protected function assertGroup(string $group): void
    {
        if (! in_array($group, ['customer', 'admin'], true)) {
            throw new OAuthProviderException('Group must be "customer" or "admin".');
        }
    }

    protected function buildClient(string $group, string $redirectUri): Apple
    {
        if ($group === 'customer') {
            if (! $this->isEnabledForCustomer()) {
                throw new OAuthProviderException('Apple OAuth is not enabled for customer.');
            }

            return new Apple([
                'clientId' => (string) $this->customerClientId,
                'teamId' => (string) $this->customerTeamId,
                'keyFileId' => (string) $this->customerKeyId,
                'keyFilePath' => (string) $this->customerPrivateKeyPath,
                'redirectUri' => $redirectUri,
            ]);
        }

        if (! $this->isEnabledForAdmin()) {
            throw new OAuthProviderException('Apple OAuth is not enabled for admin.');
        }

        return new Apple([
            'clientId' => (string) $this->adminClientId,
            'teamId' => (string) $this->adminTeamId,
            'keyFileId' => (string) $this->adminKeyId,
            'keyFilePath' => (string) $this->adminPrivateKeyPath,
            'redirectUri' => $redirectUri,
        ]);
    }
}
