<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenVerifierInterface;

abstract class AbstractMagicLinkVerifyController
{
    use FirewallRedirectTrait;
    use FlashHelperTrait;

    public function __construct(
        protected MagicLinkTokenVerifierInterface $verifier,
        protected TokenStorageInterface $tokenStorage,
        protected RouterInterface $router,
        protected ClockInterface $clock,
        protected LoggerInterface $logger,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request, string $token): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        // Idempotency: if the visitor is already fully authenticated (e.g. they
        // clicked the emailed link twice, or while already logged in), don't
        // re-consume the magic link — just send them on.
        if ($this->isFullyAuthenticatedUser($this->tokenStorage->getToken())) {
            return new RedirectResponse(
                $this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDefaultRedirectUrl()),
            );
        }

        $magicLink = $this->verifier->verify($token);
        if ($magicLink === null) {
            $this->logger->info($this->getLogChannel() . '.verify_failed', [
                'ip' => $request->getClientIp(),
            ]);
            $this->addFlashMessage($request, 'error', 'three_brs.ui.magic_link.invalid_or_expired');

            return new RedirectResponse($this->getMagicLinkRequestUrl());
        }

        $user = $this->getUserFromMagicLink($magicLink);

        $magicLink->setUsedAt($this->clock->now());
        $this->commitMagicLinkUsage($magicLink);

        $this->logger->info($this->getLogChannel() . '.verify_success', [
            'user_id' => $user->getUserIdentifier(),
            'ip' => $request->getClientIp(),
        ]);

        $this->authenticate($request, $user);

        return new RedirectResponse(
            $this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDefaultRedirectUrl()),
        );
    }

    abstract protected function isFullyAuthenticatedUser(?TokenInterface $token): bool;

    abstract protected function getUserFromMagicLink(MagicLinkRecordInterface $magicLink): UserInterface;

    /**
     * Persist the "used" flag set on the magic link by the parent.
     * Plugin subclass typically calls $entityManager->flush().
     */
    abstract protected function commitMagicLinkUsage(MagicLinkRecordInterface $magicLink): void;

    abstract protected function getFirewallName(): string;

    abstract protected function getDefaultRedirectUrl(): string;

    abstract protected function getMagicLinkRequestUrl(): string;

    abstract protected function getLogChannel(): string;

    abstract protected function handlePostLogin(UserInterface $user, Request $request): void;

    protected function authenticate(Request $request, UserInterface $user): void
    {
        // Session-fixation defence: rotate the session ID before binding the
        // newly authenticated token to it, so the pre-authentication session ID
        // cannot be reused to ride the resulting authenticated session.
        if ($request->hasSession()) {
            $request->getSession()->migrate(true);
        }

        $token = new PostAuthenticationToken($user, $this->getFirewallName(), $user->getRoles());
        $this->tokenStorage->setToken($token);

        if ($request->hasSession()) {
            $request->getSession()->set('_security_' . $this->getFirewallName(), serialize($token));
        }

        // Magic-link login writes the token directly (like OAuth and passkey),
        // intentionally bypassing the firewall authenticator — and with it scheb's
        // two-factor challenge. The second factor only guards plain password login.
        // Writing the token directly also means Symfony's LoginSuccessEvent never
        // fires, so session tracking / new-device notifications run through the
        // post-login hook below.
        $this->handlePostLogin($user, $request);
    }
}
