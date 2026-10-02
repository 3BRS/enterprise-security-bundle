<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\TwoFactor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Scheb\TwoFactorBundle\Security\Authorization\TwoFactorAccessDecider;
use Scheb\TwoFactorBundle\Security\Http\Utils\RequestDataReader;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvents;
use Scheb\TwoFactorBundle\Security\TwoFactor\TwoFactorFirewallConfig;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\HttpUtils;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\PendingSignInCanceller;

#[CoversClass(PendingSignInCanceller::class)]
class PendingSignInCancellerTest extends TestCase
{
    protected const PUBLIC_PATHS = ['/login', '/register', '/2fa', '/2fa_check', '/2fa/recovery'];

    public function testSubscribesToTheCodePageAndToRequestsAfterTheFirewall(): void
    {
        $events = PendingSignInCanceller::getSubscribedEvents();

        self::assertSame('markCodePageShown', $events[TwoFactorAuthenticationEvents::FORM]);
        self::assertSame(['cancelOnPublicPage', 7], $events[KernelEvents::REQUEST]);
    }

    public function testOpeningAPublicPageAfterTheCodePageCancelsTheSignIn(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);
        $canceller->markCodePageShown($this->codePageShown($token));

        $request = $this->createRequest('/register');
        $request->getSession()->set('_security.shop.target_path', 'http://localhost/account');
        $canceller->cancelOnPublicPage($this->requestEvent($request));

        self::assertNull($tokenStorage->getToken());
        self::assertFalse($request->getSession()->has('_security.shop.target_path'));
    }

    public function testOpeningAPublicPageBeforeTheCodePageKeepsTheSignIn(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);

        $this->makeCanceller($tokenStorage)->cancelOnPublicPage($this->requestEvent($this->createRequest('/register')));

        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testOpeningTheSignInPageCancelsTheSignInBeforeTheCodePage(): void
    {
        $tokenStorage = new TokenStorage();
        $this->startSignIn($tokenStorage);

        $request = $this->createRequest('/login');
        $request->attributes->set('_route', 'app_login');
        $this->makeCanceller($tokenStorage)->cancelOnPublicPage($this->requestEvent($request));

        self::assertNull($tokenStorage->getToken());
    }

    /**
     * The check path takes only POST by default (scheb's `post_only`), which never cancels.
     *
     * @return iterable<string, array{string, ?string, array<string, mixed>}>
     */
    public static function provideTwoFactorPages(): iterable
    {
        yield 'code page' => ['/2fa', null, []];
        yield 'code check' => [
            '/2fa_check',
            null,
            [
                'post_only' => false,
            ],
        ];
        yield 'recovery-code page' => ['/2fa/recovery', 'app_2fa_recovery', []];
    }

    /**
     * @param array<string, mixed> $firewallOptions
     */
    #[DataProvider('provideTwoFactorPages')]
    public function testTwoFactorPagesKeepTheSignIn(string $path, ?string $route, array $firewallOptions): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage, $firewallOptions);
        $canceller->markCodePageShown($this->codePageShown($token));

        $request = $this->createRequest($path);
        $request->attributes->set('_route', $route);
        $canceller->cancelOnPublicPage($this->requestEvent($request));

        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testPageThatIsNotPublicIsLeftToTheRequiredHandler(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);
        $canceller->markCodePageShown($this->codePageShown($token));

        $canceller->cancelOnPublicPage($this->requestEvent($this->createRequest('/account')));

        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testOpeningAnotherPageAfterTheCodePageCancelsTheSignIn(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);
        $canceller->markCodePageShown($this->codePageShown($token));

        $request = $this->createRequest('/', [
            'Sec-Fetch-Mode' => 'navigate',
            'Sec-Fetch-Dest' => 'document',
        ]);

        self::assertTrue($canceller->cancelOnPageLoad($request));
        self::assertNull($tokenStorage->getToken());
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideRequestsThatAreNotPageLoads(): iterable
    {
        yield 'XMLHttpRequest' => [
            'GET',
            [
                'X-Requested-With' => 'XMLHttpRequest',
            ],
        ];
        yield 'fetch' => [
            'GET',
            [
                'Sec-Fetch-Mode' => 'cors',
                'Sec-Fetch-Dest' => 'empty',
            ],
        ];
        yield 'frame' => [
            'GET',
            [
                'Sec-Fetch-Mode' => 'navigate',
                'Sec-Fetch-Dest' => 'iframe',
            ],
        ];
        yield 'prefetch' => [
            'GET',
            [
                'Sec-Fetch-Mode' => 'navigate',
                'Sec-Fetch-Dest' => 'document',
                'Sec-Purpose' => 'prefetch',
            ],
        ];
        yield 'legacy prefetch' => [
            'GET',
            [
                'Purpose' => 'prefetch',
            ],
        ];
        yield 'Firefox prefetch' => [
            'GET',
            [
                'X-Moz' => 'prefetch',
            ],
        ];
        yield 'Safari preview' => [
            'GET',
            [
                'X-Purpose' => 'preview',
            ],
        ];
        yield 'image without Sec-Fetch headers' => [
            'GET',
            [
                'Accept' => 'image/avif,image/webp,*/*',
            ],
        ];
        yield 'fetch without Sec-Fetch headers' => [
            'GET',
            [
                'Accept' => '*/*',
            ],
        ];
        yield 'form submission' => ['POST', []];
    }

    /**
     * @param array<string, string> $headers
     */
    #[DataProvider('provideRequestsThatAreNotPageLoads')]
    public function testRequestThatIsNotAPageLoadKeepsTheSignIn(string $method, array $headers): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);
        $canceller->markCodePageShown($this->codePageShown($token));

        $request = $this->createRequest('/account', $headers, $method);

        self::assertFalse($canceller->cancelOnPageLoad($request));
        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testBackgroundRequestToTheCodePageDoesNotCountAsShowingIt(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);

        $canceller->markCodePageShown($this->codePageShown($token, [
            'X-Requested-With' => 'XMLHttpRequest',
        ]));

        self::assertFalse($canceller->cancelOnPageLoad($this->createRequest('/account')));
        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testAnotherFirewallsSignInIsKept(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage, 'admin');

        $request = $this->createRequest('/login');
        $request->attributes->set('_route', 'app_login');

        self::assertFalse($this->makeCanceller($tokenStorage)->cancelOnPageLoad($request));
        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testSubRequestIsIgnored(): void
    {
        $tokenStorage = new TokenStorage();
        $token = $this->startSignIn($tokenStorage);
        $canceller = $this->makeCanceller($tokenStorage);
        $canceller->markCodePageShown($this->codePageShown($token));

        $canceller->cancelOnPublicPage($this->requestEvent($this->createRequest('/register'), HttpKernelInterface::SUB_REQUEST));

        self::assertSame($token, $tokenStorage->getToken());
    }

    public function testRequestWithoutASessionCookieDoesNotLoadTheToken(): void
    {
        // A sign-in in progress lives in the session, and loading the token for a visitor without one
        // would start a session on every public page.
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('getToken');

        $request = Request::create('/register');
        $request->setSession(new Session(new MockArraySessionStorage()));

        $this->makeCanceller($tokenStorage)->cancelOnPublicPage($this->requestEvent($request));
    }

    /**
     * @param array<string, mixed> $firewallOptions
     */
    protected function makeCanceller(TokenStorageInterface $tokenStorage, array $firewallOptions = []): PendingSignInCanceller
    {
        $accessDecider = $this->createStub(TwoFactorAccessDecider::class);
        $accessDecider->method('isPubliclyAccessible')->willReturnCallback(
            static fn (Request $request): bool => in_array($request->getPathInfo(), static::PUBLIC_PATHS, true),
        );

        $firewallConfig = new TwoFactorFirewallConfig(
            array_merge([
                'auth_form_path' => '/2fa',
                'check_path' => '/2fa_check',
            ], $firewallOptions),
            'shop',
            new HttpUtils(),
            new RequestDataReader(),
        );

        return new PendingSignInCanceller($tokenStorage, $accessDecider, $firewallConfig, ['app_login'], ['app_2fa_recovery']);
    }

    protected function startSignIn(TokenStorageInterface $tokenStorage, string $firewall = 'shop'): TwoFactorToken
    {
        $user = new InMemoryUser('ted@example.com', null, ['ROLE_USER']);
        $token = new TwoFactorToken(new UsernamePasswordToken($user, $firewall, $user->getRoles()), null, $firewall, ['totp']);
        $tokenStorage->setToken($token);

        return $token;
    }

    /**
     * @param array<string, string> $headers
     */
    protected function codePageShown(TwoFactorToken $token, array $headers = []): TwoFactorAuthenticationEvent
    {
        return new TwoFactorAuthenticationEvent($this->createRequest('/2fa', $headers), $token);
    }

    /**
     * @param array<string, string> $headers
     */
    protected function createRequest(string $path, array $headers = [], string $method = 'GET'): Request
    {
        $session = new Session(new MockArraySessionStorage());
        $request = Request::create($path, $method);
        $request->headers->add($headers);
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'session-id');

        return $request;
    }

    protected function requestEvent(Request $request, int $type = HttpKernelInterface::MAIN_REQUEST): RequestEvent
    {
        return new RequestEvent($this->createStub(HttpKernelInterface::class), $request, $type);
    }
}
