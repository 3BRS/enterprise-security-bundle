<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionVerifierInterface;

abstract class AbstractPasskeyLoginVerifyController
{
    use FirewallRedirectTrait;

    public function __construct(
        protected PasskeyAssertionVerifierInterface $verifier,
        protected TokenStorageInterface $tokenStorage,
        protected RouterInterface $router,
        protected LoggerInterface $logger,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        try {
            $payload = json_decode($request->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return new JsonResponse([
                'error' => 'Missing credential payload.',
            ], Response::HTTP_BAD_REQUEST);
        }
        $credentialJson = is_array($payload) ? ($payload['credential'] ?? null) : null;
        if (! is_string($credentialJson) || $credentialJson === '') {
            return new JsonResponse([
                'error' => 'Missing credential payload.',
            ], Response::HTTP_BAD_REQUEST);
        }

        try {
            $result = $this->verifier->verify($credentialJson, $request->getHost());
        } catch (\Throwable $exception) {
            $this->logger->info($this->getLogChannel() . '.assertion_failed', [
                'reason' => $exception->getMessage(),
                'ip' => $request->getClientIp(),
            ]);

            return new JsonResponse([
                'error' => 'Passkey assertion failed.',
            ], Response::HTTP_BAD_REQUEST);
        }

        $this->authenticate($request, $result->getUser());

        $redirectUrl = $this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDefaultRedirectUrl());

        return new JsonResponse([
            'ok' => true,
            'redirect' => $redirectUrl,
        ]);
    }

    abstract protected function getFirewallName(): string;

    abstract protected function getDefaultRedirectUrl(): string;

    abstract protected function getLogChannel(): string;

    abstract protected function handlePostLogin(UserInterface $user, Request $request): void;

    protected function authenticate(Request $request, UserInterface $user): void
    {
        // Session-fixation defence: rotate the session ID before binding the
        // newly authenticated token, so the pre-authentication session ID cannot
        // be reused to ride the resulting authenticated session.
        if ($request->hasSession()) {
            $request->getSession()->migrate(true);
        }

        $token = new PostAuthenticationToken($user, $this->getFirewallName(), $user->getRoles());
        $this->tokenStorage->setToken($token);

        if ($request->hasSession()) {
            $request->getSession()->set('_security_' . $this->getFirewallName(), serialize($token));
        }

        // Passkey login writes the token directly (like OAuth and magic link),
        // intentionally bypassing the firewall authenticator — and with it scheb's
        // two-factor challenge. A passkey already proves possession of the
        // registered authenticator, so the second factor only guards plain password
        // login. Writing the token directly also means Symfony's LoginSuccessEvent
        // never fires, so session tracking / new-device notifications run through
        // the post-login hook below.
        $this->handlePostLogin($user, $request);
    }
}
