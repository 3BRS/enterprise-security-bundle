<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfo;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\SocialAccountLinkRecordInterface;
use Twig\Environment;

abstract class AbstractOAuthConfirmLinkController
{
    use FirewallRedirectTrait;
    use FlashHelperTrait;

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected RouterInterface $router,
        protected Environment $twig,
        protected LoggerInterface $logger,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $session = $request->getSession();
        $pending = $session->get($this->getConfirmPendingSessionKey());

        if (! is_array($pending) || ! isset($pending['email'], $pending['provider'], $pending['provider_user_id'])) {
            return new RedirectResponse($this->router->generate($this->getLoginRoute()));
        }

        $email = (string) $pending['email'];
        $user = $this->findUserByEmail($email);
        if ($user === null) {
            $session->remove($this->getConfirmPendingSessionKey());

            return new RedirectResponse($this->router->generate($this->getLoginRoute()));
        }

        $error = null;
        if ($request->isMethod('POST')) {
            $error = $this->verifyChallenge($user, $pending, $request);
            if ($error !== null) {
                $this->logger->info($this->getAuditChannel() . '.confirm_link_failed', [
                    'provider' => (string) $pending['provider'],
                    'email' => $email,
                    'ip' => $request->getClientIp(),
                ]);
            } else {
                $provider = (string) $pending['provider'];
                $providerUserId = (string) $pending['provider_user_id'];

                $existing = $this->findExistingLink($provider, $providerUserId);
                if ($existing !== null) {
                    $session->remove($this->getConfirmPendingSessionKey());

                    if (! $this->isLinkOwnedByUser($existing, $user)) {
                        $this->addFlashMessage($request, 'error', 'three_brs.ui.social_login.already_linked_other_account');

                        return new RedirectResponse($this->router->generate($this->getLoginRoute()));
                    }
                } else {
                    $info = new OAuthUserInfo(
                        $provider,
                        $providerUserId,
                        $email,
                        isset($pending['first_name']) ? (string) $pending['first_name'] : null,
                        isset($pending['last_name']) ? (string) $pending['last_name'] : null,
                    );

                    $this->linkExistingUser($user, $info);
                    $session->remove($this->getConfirmPendingSessionKey());
                }

                $this->logger->info($this->getAuditChannel() . '.linked_via_confirm', [
                    'provider' => $provider,
                    $this->getAuditUserIdKey() => $user->getUserIdentifier(),
                    'email' => $email,
                    'ip' => $request->getClientIp(),
                ]);

                $this->authenticate($request, $user);
                $this->addFlashMessage($request, 'success', 'three_brs.ui.social_login.linked');

                return new RedirectResponse(
                    $this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDashboardUrl()),
                );
            }
        } else {
            $this->prepareChallenge($user, $pending, $request);
        }

        return new Response($this->twig->render($this->getTemplate(), [
            'email' => $email,
            'provider' => (string) $pending['provider'],
            'error' => $error,
        ]));
    }

    protected function authenticate(Request $request, UserInterface $user): void
    {
        // Session-fixation defence: rotate the session ID before binding the
        // newly authenticated token, so a pre-auth session ID an attacker could
        // have planted cannot ride the resulting authenticated session.
        if ($request->hasSession()) {
            $request->getSession()->migrate(true);
        }

        $token = new PostAuthenticationToken($user, $this->getFirewallName(), $user->getRoles());
        $this->tokenStorage->setToken($token);

        if ($request->hasSession()) {
            $request->getSession()->set('_security_' . $this->getFirewallName(), serialize($token));
        }

        // Manual setToken bypasses the firewall event dispatcher; subclass hooks
        // into post-login here (typically: session-tracking + new-device email).
        $this->handlePostLogin($user, $request);
    }

    abstract protected function getConfirmPendingSessionKey(): string;

    abstract protected function getFirewallName(): string;

    abstract protected function getLoginRoute(): string;

    abstract protected function getDashboardUrl(): string;

    abstract protected function getTemplate(): string;

    abstract protected function getAuditChannel(): string;

    abstract protected function getAuditUserIdKey(): string;

    abstract protected function findUserByEmail(string $email): ?UserInterface;

    abstract protected function findExistingLink(string $provider, string $providerUserId): ?SocialAccountLinkRecordInterface;

    abstract protected function isLinkOwnedByUser(SocialAccountLinkRecordInterface $existing, UserInterface $user): bool;

    abstract protected function linkExistingUser(UserInterface $user, OAuthUserInfoInterface $info): void;

    abstract protected function handlePostLogin(UserInterface $user, Request $request): void;

    /**
     * Issues the ownership-proof challenge for the matched account (e.g. emails a one-time
     * code). Called on the initial GET render and should be idempotent across refreshes
     * (only (re)issue when needed). May stash challenge state into the pending session array
     * stored under {@see getConfirmPendingSessionKey()}.
     *
     * @param array<string, mixed> $pending
     */
    abstract protected function prepareChallenge(UserInterface $user, array $pending, Request $request): void;

    /**
     * Verifies the submitted ownership proof on POST. Returns null on success, otherwise a
     * translation key describing the failure (rendered back on the confirm-link page).
     *
     * @param array<string, mixed> $pending
     */
    abstract protected function verifyChallenge(UserInterface $user, array $pending, Request $request): ?string;
}
