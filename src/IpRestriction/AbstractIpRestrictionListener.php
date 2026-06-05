<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\IpRestriction;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Generic kernel.request listener for global IP-restriction enforcement
 * (whitelist OR blacklist). Handles the framework plumbing — main-request
 * check, admin path prefix match, client IP resolution, 403 plain-text
 * response on deny. The check is identity-agnostic: a global CIDR list applies
 * to every request regardless of which user (if any) is authenticated.
 * Subclass plugs in the feature toggle + the allow/deny decision (which is
 * where the whitelist↔blacklist semantic inversion lives).
 */
abstract class AbstractIpRestrictionListener
{
    public function __construct(
        protected string $adminPathPrefix = '/admin',
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        if (! $this->isFeatureEnabled()) {
            return;
        }

        $request = $event->getRequest();
        $path = $request->getPathInfo();

        // Match `/admin` exactly and `/admin/...` — but not `/admin-anything`,
        // which would otherwise slip past a naive `str_starts_with($path, '/admin')`.
        if ($path !== $this->adminPathPrefix && ! str_starts_with($path, $this->adminPathPrefix . '/')) {
            return;
        }

        $ip = (string) $request->getClientIp();

        if ($this->isRequestAllowed($ip)) {
            return;
        }

        $event->setResponse(new Response(
            'Access denied',
            Response::HTTP_FORBIDDEN,
            [
                'Content-Type' => 'text/plain; charset=UTF-8',
            ],
        ));
    }

    abstract protected function isFeatureEnabled(): bool;

    /**
     * Return true when the request should pass through, false when the listener
     * should deny with 403. Whitelist subclass returns the checker's "matches"
     * result; blacklist subclass returns its inverse.
     */
    abstract protected function isRequestAllowed(string $ip): bool;
}
