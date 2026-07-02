<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSignerInterface;

abstract class AbstractOAuthInitiateController
{
    protected const STATE_COOKIE_LIFETIME = 600;

    public function __construct(
        protected OAuthProviderRegistryInterface $registry,
        protected RouterInterface $router,
        protected StateCookieSignerInterface $stateCookieSigner,
        protected ?Security $security = null,
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

        $response = new RedirectResponse($url);

        // Providers whose callback is a cross-site POST (response_mode=form_post, e.g. Apple)
        // never receive the SameSite=Lax session cookie on the callback, so the OAuth state
        // (and, for a link, the initiating user) would be lost. Carry them in a dedicated
        // SameSite=None; Secure; HttpOnly single-use cookie that survives the cross-site POST;
        // the callback reads and clears it. The session keeps working unchanged for normal
        // GET-redirect providers (Google, Microsoft).
        if ($oauth instanceof FormPostOAuthProviderInterface) {
            $response->headers->setCookie($this->createStateCookie($provider, $state, $intent));
        }

        return $response;
    }

    protected function createStateCookie(string $provider, string $state, string $intent): Cookie
    {
        $payload = [
            'state' => $state,
            'intent' => $intent,
        ];

        // A link is started by an authenticated user, but that identity is read from the
        // session — which is absent on the cross-site form_post callback. Carry the user's
        // identifier so the callback can still resolve them. (Login needs no user here.)
        if ($intent === 'link' && $this->security !== null) {
            $user = $this->security->getUser();
            if ($user !== null) {
                $payload['user'] = $user->getUserIdentifier();
            }
        }

        return Cookie::create(
            $this->getStateSessionKey() . '_' . $provider,
            $this->stateCookieSigner->encode($payload),
            time() + static::STATE_COOKIE_LIFETIME,
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_NONE,
        );
    }

    abstract protected function isProviderEnabledForScope(OAuthProviderInterface $provider): bool;

    abstract protected function getOAuthGroup(): string;

    abstract protected function getStateSessionKey(): string;

    abstract protected function getIntentSessionKey(): string;

    abstract protected function getCallbackRouteName(): string;
}
