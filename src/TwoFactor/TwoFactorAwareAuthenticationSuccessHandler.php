<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

class TwoFactorAwareAuthenticationSuccessHandler implements TwoFactorAwareAuthenticationSuccessHandlerInterface
{
    public function __construct(
        protected AuthenticationRequiredHandlerInterface $twoFactorAuthenticationRequiredHandler,
        protected AuthenticationSuccessHandlerInterface $defaultSuccessHandler,
    ) {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): ?Response
    {
        if ($token instanceof TwoFactorTokenInterface) {
            return $this->twoFactorAuthenticationRequiredHandler->onAuthenticationRequired($request, $token);
        }

        return $this->defaultSuccessHandler->onAuthenticationSuccess($request, $token);
    }
}
