<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Security\Http\Authentication\AuthenticationRequiredHandlerInterface;

interface CancelPendingSignInRequiredHandlerInterface extends AuthenticationRequiredHandlerInterface
{
}
