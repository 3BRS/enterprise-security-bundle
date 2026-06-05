<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

trait FirewallRedirectTrait
{
    use TargetPathTrait;

    protected function resolveRedirectUrl(Request $request, string $firewallName, string $defaultUrl): string
    {
        if (! $request->hasSession()) {
            return $defaultUrl;
        }

        $session = $request->getSession();
        $targetPath = $this->getTargetPath($session, $firewallName);
        if (is_string($targetPath) && $targetPath !== '') {
            $this->removeTargetPath($session, $firewallName);

            return $targetPath;
        }

        return $defaultUrl;
    }
}
