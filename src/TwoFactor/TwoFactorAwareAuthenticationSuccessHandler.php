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

    /**
     * Symfony hands the firewall's success-handler options (default_target_path, use_referer, …) only
     * to the handler named in security.yaml. The wrapped handler is a shared service, so they go to a
     * copy of it — another firewall wrapping the same service keeps its own.
     *
     * @param array<string, mixed> $options
     */
    public function setOptions(array $options): void
    {
        if (method_exists($this->defaultSuccessHandler, 'setOptions')) {
            $handler = clone $this->defaultSuccessHandler;
            $handler->setOptions($options);
            $this->defaultSuccessHandler = $handler;
        }
    }

    public function setFirewallName(string $firewallName): void
    {
        if (method_exists($this->defaultSuccessHandler, 'setFirewallName')) {
            $handler = clone $this->defaultSuccessHandler;
            $handler->setFirewallName($firewallName);
            $this->defaultSuccessHandler = $handler;
        }
    }
}
