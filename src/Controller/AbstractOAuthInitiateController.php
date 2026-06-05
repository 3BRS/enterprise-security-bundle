<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;

abstract class AbstractOAuthInitiateController
{
    public function __construct(
        protected OAuthProviderRegistryInterface $registry,
        protected RouterInterface $router,
    ) {
    }

    public function __invoke(Request $request, string $provider): Response
    {
        if (! $this->registry->has($provider)) {
            throw new OAuthProviderException(sprintf('Unknown OAuth provider "%s".', $provider));
        }

        $oauth = $this->registry->get($provider);
        if (! $this->isProviderEnabledForScope($oauth)) {
            throw new OAuthProviderException(sprintf('OAuth provider "%s" is disabled for %s.', $provider, $this->getOAuthGroup()));
        }

        $state = bin2hex(random_bytes(16));
        $session = $request->getSession();
        $session->set($this->getStateSessionKey() . '_' . $provider, $state);

        $intent = $request->query->getString('intent', 'login');
        if (! in_array($intent, ['login', 'link'], true)) {
            $intent = 'login';
        }
        $session->set($this->getIntentSessionKey(), $intent);

        $redirectUri = $this->router->generate(
            $this->getCallbackRouteName(),
            [
                'provider' => $provider,
            ],
            RouterInterface::ABSOLUTE_URL,
        );

        $url = $oauth->getAuthorizationUrl($redirectUri, $state, $this->getOAuthGroup());

        return new RedirectResponse($url);
    }

    abstract protected function isProviderEnabledForScope(OAuthProviderInterface $provider): bool;

    abstract protected function getOAuthGroup(): string;

    abstract protected function getStateSessionKey(): string;

    abstract protected function getIntentSessionKey(): string;

    abstract protected function getCallbackRouteName(): string;
}
