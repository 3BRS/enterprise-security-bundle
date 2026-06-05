<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

interface TwoFactorAwareAuthenticationSuccessHandlerInterface extends AuthenticationSuccessHandlerInterface
{
}
