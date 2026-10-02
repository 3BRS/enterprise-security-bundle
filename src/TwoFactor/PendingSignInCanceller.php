<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\TwoFactor;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Authorization\TwoFactorAccessDecider;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvents;
use Scheb\TwoFactorBundle\Security\TwoFactor\TwoFactorFirewallConfig;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Cancels one firewall's sign-in that waits for its two-factor code, together with the page scheb saved
 * to return to, when the user opens another page of the firewall after the code page was shown. Scheb
 * keeps such a sign-in until the session expires and sends every page that is not public back to the
 * code page.
 *
 * Public pages cancel in cancelOnPublicPage(), the others through CancelPendingSignInRequiredHandler.
 * Pages opened before the code page was shown do not cancel, except the sign-in page; the two-factor
 * pages never do.
 */
class PendingSignInCanceller implements PendingSignInCancellerInterface, EventSubscriberInterface
{
    use TargetPathTrait;

    protected const CODE_PAGE_SHOWN_ATTRIBUTE = 'three_brs_two_factor_code_page_shown';

    /**
     * @param list<string> $signInRoutes    the firewall's sign-in page; opening it cancels even before the code page was shown
     * @param list<string> $twoFactorRoutes two-factor pages besides scheb's form and check path (e.g. the recovery-code page)
     */
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected TwoFactorAccessDecider $twoFactorAccessDecider,
        protected TwoFactorFirewallConfig $twoFactorFirewallConfig,
        protected array $signInRoutes = [],
        protected array $twoFactorRoutes = [],
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            TwoFactorAuthenticationEvents::FORM => 'markCodePageShown',
            // The firewall listens at priority 8.
            KernelEvents::REQUEST => ['cancelOnPublicPage', 7],
        ];
    }

    /**
     * Scheb dispatches FORM for every request to the code page, background ones included.
     */
    public function markCodePageShown(TwoFactorAuthenticationEvent $event): void
    {
        $token = $event->getToken();
        if ($this->isPendingSignIn($token) && $this->isPageLoad($event->getRequest())) {
            $token->setAttribute(static::CODE_PAGE_SHOWN_ATTRIBUTE, true);
        }
    }

    public function cancelOnPublicPage(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (
            $event->isMainRequest()
            && $request->hasPreviousSession()
            && $this->twoFactorAccessDecider->isPubliclyAccessible($request)
        ) {
            $this->cancelOnPageLoad($request);
        }
    }

    public function cancelOnPageLoad(Request $request): bool
    {
        if (! $this->isPageLoad($request) || $this->isTwoFactorPage($request)) {
            return false;
        }

        $token = $this->tokenStorage->getToken();
        if (! $this->isPendingSignIn($token)) {
            return false;
        }

        if (! $token->hasAttribute(static::CODE_PAGE_SHOWN_ATTRIBUTE) && ! $this->isSignInPage($request)) {
            return false;
        }

        $this->tokenStorage->setToken(null);
        if ($request->hasSession()) {
            $this->removeTargetPath($request->getSession(), $this->twoFactorFirewallConfig->getFirewallName());
        }

        return true;
    }

    /**
     * @phpstan-assert-if-true TwoFactorTokenInterface $token
     */
    protected function isPendingSignIn(?TokenInterface $token): bool
    {
        return $token instanceof TwoFactorTokenInterface
            && $token->getFirewallName() === $this->twoFactorFirewallConfig->getFirewallName();
    }

    /**
     * A page opened in the browser window, not a background request, a frame or a prefetch. Browsers
     * send the Sec-Fetch headers to secure origins only; without them the Accept header tells a page
     * from an image or a fetch().
     */
    protected function isPageLoad(Request $request): bool
    {
        if (! $request->isMethodSafe() || $request->isXmlHttpRequest() || $this->isPrefetch($request)) {
            return false;
        }

        if (! $request->headers->has('Sec-Fetch-Mode')) {
            return str_contains((string) $request->headers->get('Accept', ''), 'text/html');
        }

        return $request->headers->get('Sec-Fetch-Mode') === 'navigate'
            && $request->headers->get('Sec-Fetch-Dest', 'document') === 'document';
    }

    protected function isPrefetch(Request $request): bool
    {
        return $request->headers->has('Sec-Purpose')
            || $request->headers->has('Purpose')
            || $request->headers->has('X-Purpose')
            || $request->headers->get('X-Moz') === 'prefetch';
    }

    protected function isTwoFactorPage(Request $request): bool
    {
        return $this->twoFactorFirewallConfig->isAuthFormRequest($request)
            || $this->twoFactorFirewallConfig->isCheckPathRequest($request)
            || in_array($request->attributes->get('_route'), $this->twoFactorRoutes, true);
    }

    protected function isSignInPage(Request $request): bool
    {
        return in_array($request->attributes->get('_route'), $this->signInRoutes, true);
    }
}
