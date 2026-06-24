<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\Exception\OAuthProviderException;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\FormPostOAuthProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthProviderRegistryInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSignerInterface;

abstract class AbstractOAuthCallbackController
{
    use FirewallRedirectTrait;
    use FlashHelperTrait;

    public function __construct(
        protected OAuthProviderRegistryInterface $registry,
        protected RouterInterface $router,
        protected TokenStorageInterface $tokenStorage,
        protected Security $security,
        protected LoggerInterface $logger,
        protected StateCookieSignerInterface $stateCookieSigner,
    ) {
    }

    public function __invoke(Request $request, string $provider): Response
    {
        if (! $this->registry->has($provider)) {
            throw new OAuthProviderException(sprintf('Unknown OAuth provider "%s".', $provider));
        }

        $oauthProvider = $this->registry->get($provider);
        $isFormPost = $oauthProvider instanceof FormPostOAuthProviderInterface;

        $session = $request->getSession();
        $linkUserIdentifier = null;

        if ($isFormPost) {
            // Cross-site form_post callback (e.g. Apple): the SameSite=Lax session cookie is
            // not sent, so state / intent / link-user travel in the dedicated SameSite=None
            // cookie set on initiate.
            [$expectedState, $intent, $linkUserIdentifier] = $this->readStateCookie($request, $provider);
        } else {
            $expectedState = (string) $session->get($this->getStateSessionKey() . '_' . $provider, '');
            $session->remove($this->getStateSessionKey() . '_' . $provider);
            $intent = (string) $session->get($this->getIntentSessionKey(), 'login');
            $session->remove($this->getIntentSessionKey());
        }

        $redirectUri = $this->router->generate(
            $this->getCallbackRouteName(),
            [
                'provider' => $provider,
            ],
            RouterInterface::ABSOLUTE_URL,
        );

        try {
            $info = $oauthProvider->fetchUserInfo($request, $redirectUri, $expectedState, $this->getOAuthGroup());
        } catch (OAuthProviderException $exception) {
            $this->addFlashMessage($request, 'error', $exception->getMessage());

            return $this->withClearedStateCookie(
                new RedirectResponse($this->router->generate($this->getLoginRoute())),
                $isFormPost,
                $provider,
            );
        }

        $response = $intent === 'link'
            ? $this->handleLinkIntent($request, $info, $linkUserIdentifier)
            : $this->handleLoginIntent($request, $info);

        return $this->withClearedStateCookie($response, $isFormPost, $provider);
    }

    protected function handleLinkIntent(Request $request, OAuthUserInfoInterface $info, ?string $linkUserIdentifier = null): Response
    {
        $currentUser = $this->security->getUser();
        $sessionlessLink = false;

        // Cross-site form_post callback (e.g. Apple): the auth session cookie is not sent, so
        // the logged-in user cannot be read from the security context. The initiate step
        // captured the authenticated user's identifier into the single-use state cookie;
        // resolve them from it. The link is thus bound to that cookie value rather than a live
        // session — acceptable because the cookie is HttpOnly + Secure + SameSite=None +
        // single-use and the OAuth state is validated. (A stricter alternative is to complete
        // the link on a follow-up same-site request; see docs/oauth-social-login.md.)
        if ($currentUser === null && $linkUserIdentifier !== null && $linkUserIdentifier !== '') {
            $currentUser = $this->findUserByIdentifier($linkUserIdentifier);
            $sessionlessLink = true;
        }

        if (! $this->isAcceptableCurrentUser($currentUser)) {
            $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.not_logged_in');

            return new RedirectResponse($this->router->generate($this->getLoginRoute()));
        }
        \assert($currentUser instanceof UserInterface);

        // The cross-site form_post callback carried no session, so the response will set a
        // brand-new session cookie (triggered by the flash writes below) that overwrites the
        // user's real one — silently signing them out. Re-establish their authenticated
        // session first so linking keeps them logged in.
        if ($sessionlessLink) {
            $this->authenticate($request, $currentUser);
        }

        $existing = $this->findExistingLinkUser($info);
        if ($existing !== null && $existing->getUserIdentifier() !== $currentUser->getUserIdentifier()) {
            $this->auditLog('link_refused_owned_by_other', $info, $request, [
                $this->getAuditUserIdKey() => $currentUser->getUserIdentifier(),
            ]);
            $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.already_linked_other_account');

            return new RedirectResponse($this->router->generate($this->getSocialAccountsRoute()));
        }

        if ($existing !== null) {
            $this->addFlashMessage($request, 'info', 'three_brs.ui.social_login.already_linked');

            return new RedirectResponse($this->router->generate($this->getSocialAccountsRoute()));
        }

        $this->linkExistingUser($currentUser, $info);
        $this->auditLog('linked', $info, $request, [
            $this->getAuditUserIdKey() => $currentUser->getUserIdentifier(),
        ]);
        $this->addFlashMessage($request, 'success', 'three_brs.ui.social_login.linked');

        return new RedirectResponse($this->router->generate($this->getSocialAccountsRoute()));
    }

    protected function handleLoginIntent(Request $request, OAuthUserInfoInterface $info): Response
    {
        $existing = $this->findExistingLinkUser($info);
        if ($existing !== null) {
            $this->touchLastUsed($existing, $info);
            $this->authenticate($request, $existing);
            $this->auditLog('login_success', $info, $request, [
                $this->getAuditUserIdKey() => $existing->getUserIdentifier(),
            ]);

            return new RedirectResponse($this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDashboardUrl()));
        }

        $email = $info->getEmail();
        if ($email === null || $email === '') {
            $this->auditLog('register_refused_missing_email', $info, $request);
            $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.missing_email');

            return new RedirectResponse($this->router->generate($this->getLoginRoute()));
        }

        $userByEmail = $this->findUserByEmail($email);
        if ($userByEmail !== null) {
            $request->getSession()->set($this->getConfirmPendingSessionKey(), [
                'provider' => $info->getProvider(),
                'provider_user_id' => $info->getProviderUserId(),
                'email' => $info->getEmail(),
                'first_name' => $info->getFirstName(),
                'last_name' => $info->getLastName(),
            ]);

            return new RedirectResponse($this->router->generate($this->getConfirmLinkRoute()));
        }

        if (! $this->canAutoRegister($info)) {
            $this->auditLog('register_refused', $info, $request);
            $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.auto_register_refused');

            return new RedirectResponse($this->router->generate($this->getLoginRoute()));
        }

        $newUser = $this->registerAndLink($info);
        $this->authenticate($request, $newUser);
        $this->auditLog('registered_and_logged_in', $info, $request, [
            $this->getAuditUserIdKey() => $newUser->getUserIdentifier(),
        ]);

        return new RedirectResponse($this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDashboardUrl()));
    }

    protected function authenticate(Request $request, UserInterface $user): void
    {
        // Session-fixation defence: rotate the session ID before binding the
        // newly authenticated token to it, so the pre-authentication session ID
        // (which an attacker could have planted via XSS / set-cookie injection)
        // cannot be reused to ride the resulting authenticated session.
        if ($request->hasSession()) {
            $request->getSession()->migrate(true);
        }

        $token = new PostAuthenticationToken($user, $this->getFirewallName(), $user->getRoles());
        $this->tokenStorage->setToken($token);

        if ($request->hasSession()) {
            $request->getSession()->set('_security_' . $this->getFirewallName(), serialize($token));
        }

        // Symfony's LoginSuccessEvent is dispatched by the firewall authenticator;
        // OAuth bypasses that machinery and writes the token directly, so the
        // standard session-tracking listener never fires. Subclass hooks here.
        $this->handlePostLogin($user, $request);
    }

    /**
     * @param array<string, mixed> $extra
     */
    protected function auditLog(string $event, OAuthUserInfoInterface $info, Request $request, array $extra = []): void
    {
        $this->logger->info(sprintf('%s.%s', $this->getAuditChannel(), $event), array_merge([
            'provider' => $info->getProvider(),
            'provider_user_id' => $info->getProviderUserId(),
            'email' => $info->getEmail(),
            'ip' => $request->getClientIp(),
        ], $extra));
    }

    /**
     * Reads the dedicated state cookie set on initiate for form_post providers.
     *
     * @return array{0: string, 1: string, 2: ?string} the expected state, the intent, and the
     *                                                  link-initiating user identifier (if any)
     */
    protected function readStateCookie(Request $request, string $provider): array
    {
        $raw = $request->cookies->get($this->getStateSessionKey() . '_' . $provider);
        // Verify the HMAC before trusting any field: the cookie travels on a cross-site request
        // an attacker can craft directly, so an unsigned/forged value (e.g. `user` set to a
        // victim) must be rejected rather than decoded.
        $decoded = is_string($raw) && $raw !== '' ? $this->stateCookieSigner->decode($raw) : null;
        if (! is_array($decoded)) {
            return ['', 'login', null];
        }

        $state = isset($decoded['state']) && is_string($decoded['state']) ? $decoded['state'] : '';
        $intent = isset($decoded['intent']) && is_string($decoded['intent']) ? $decoded['intent'] : 'login';
        if (! in_array($intent, ['login', 'link'], true)) {
            $intent = 'login';
        }
        $user = isset($decoded['user']) && is_string($decoded['user']) ? $decoded['user'] : null;

        return [$state, $intent, $user];
    }

    protected function withClearedStateCookie(Response $response, bool $isFormPost, string $provider): Response
    {
        if ($isFormPost) {
            // Single-use: drop the dedicated state cookie once the callback has consumed it.
            $response->headers->clearCookie(
                $this->getStateSessionKey() . '_' . $provider,
                '/',
                null,
                true,
                true,
                Cookie::SAMESITE_NONE,
            );
        }

        return $response;
    }

    abstract protected function getOAuthGroup(): string;

    abstract protected function getCallbackRouteName(): string;

    abstract protected function getFirewallName(): string;

    abstract protected function getStateSessionKey(): string;

    abstract protected function getIntentSessionKey(): string;

    abstract protected function getConfirmPendingSessionKey(): string;

    abstract protected function getLoginRoute(): string;

    abstract protected function getDashboardUrl(): string;

    abstract protected function getSocialAccountsRoute(): string;

    abstract protected function getConfirmLinkRoute(): string;

    abstract protected function getAuditChannel(): string;

    abstract protected function getAuditUserIdKey(): string;

    abstract protected function isAcceptableCurrentUser(?UserInterface $user): bool;

    abstract protected function findExistingLinkUser(OAuthUserInfoInterface $info): ?UserInterface;

    abstract protected function findUserByEmail(string $email): ?UserInterface;

    /**
     * Resolves a user from the firewall's identifier (used to recover the link-initiating
     * user on a cross-site form_post callback where the session is unavailable).
     */
    abstract protected function findUserByIdentifier(string $identifier): ?UserInterface;

    abstract protected function canAutoRegister(OAuthUserInfoInterface $info): bool;

    abstract protected function registerAndLink(OAuthUserInfoInterface $info): UserInterface;

    abstract protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void;

    abstract protected function touchLastUsed(UserInterface $user, OAuthUserInfoInterface $info): void;

    abstract protected function handlePostLogin(UserInterface $user, Request $request): void;
}
