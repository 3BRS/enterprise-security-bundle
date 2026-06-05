<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authenticator\TwoFactorAuthenticator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;

abstract class AbstractTwoFactorRecoveryChallengeController
{
    use FirewallRedirectTrait;

    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected RouterInterface $router,
        protected Environment $twig,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $token = $this->tokenStorage->getToken();
        if (! $token instanceof TwoFactorTokenInterface) {
            throw new AccessDeniedException('User is not in a two-factor authentication process.');
        }

        $user = $token->getUser();
        if (! $this->isAcceptableUser($user)) {
            throw new AccessDeniedException('Invalid user.');
        }

        $error = null;
        if ($request->isMethod('POST')) {
            $code = trim((string) $request->request->get('_recovery_code'));
            if ($code === '') {
                $error = 'three_brs.ui.two_factor.recovery_code_required';
            } elseif (! $this->verifyAndConsumeRecoveryCode($user, $code)) {
                $error = 'three_brs.ui.two_factor.invalid_recovery_code';
            } else {
                $authenticatedToken = $token->getAuthenticatedToken();
                $authenticatedToken->setAttribute(TwoFactorAuthenticator::FLAG_2FA_COMPLETE, true);
                $this->tokenStorage->setToken($authenticatedToken);

                return new RedirectResponse(
                    $this->resolveRedirectUrl($request, $this->getFirewallName(), $this->getDefaultRedirectUrl()),
                );
            }
        }

        return new Response($this->twig->render($this->getTemplate(), [
            'error' => $error,
        ]));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function verifyAndConsumeRecoveryCode(UserInterface $user, string $code): bool;

    abstract protected function getFirewallName(): string;

    abstract protected function getDefaultRedirectUrl(): string;

    abstract protected function getTemplate(): string;
}
