<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenVerifierInterface;

abstract class AbstractMagicLinkVerifyController
{
    use FirewallRedirectTrait;
    use FlashHelperTrait;

    public function __construct(
        protected MagicLinkTokenVerifierInterface $verifier,
        protected TokenStorageInterface $tokenStorage,
        protected EventDispatcherInterface $eventDispatcher,
        protected AuthenticationRequiredHandlerInterface $twoFactorHandler,
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

        // Post-2FA redirect-back idempotency: scheb/2fa's prepare_on_login saves the
        // current URL as the post-2FA target_path, so once 2FA succeeds the user lands
        // back here. At that point the magic link has already done its job.
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

        $authenticatedToken = $this->authenticate($request, $user);

        if ($authenticatedToken instanceof TwoFactorTokenInterface) {
            return $this->twoFactorHandler->onAuthenticationRequired($request, $authenticatedToken);
        }

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

    protected function authenticate(Request $request, UserInterface $user): TokenInterface
    {
        $userIdentifier = $user->getUserIdentifier();
        $passport = new SelfValidatingPassport(new UserBadge($userIdentifier, static fn () => $user));
        $token = new PostAuthenticationToken($user, $this->getFirewallName(), $user->getRoles());

        $event = new AuthenticationTokenCreatedEvent($token, $passport);
        $this->eventDispatcher->dispatch($event);

        $resultToken = $event->getAuthenticatedToken();

        // Session-fixation defence: rotate the session ID before binding the
        // newly authenticated token. The magic-link flow goes through a custom
        // passport-less login path that would otherwise inherit the pre-login ID.
        if ($request->hasSession()) {
            $request->getSession()->migrate(true);
        }

        $this->tokenStorage->setToken($resultToken);

        if ($request->hasSession()) {
            $request->getSession()->set('_security_' . $this->getFirewallName(), serialize($resultToken));
        }

        // Manual setToken bypasses the firewall event dispatcher, so the
        // LoginSuccessEvent listener that tracks sessions / sends new-device
        // notifications never fires. Subclass hooks into post-login here.
        $this->handlePostLogin($user, $request);

        return $resultToken;
    }
}
