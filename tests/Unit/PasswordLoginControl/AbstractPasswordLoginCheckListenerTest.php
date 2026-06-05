<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\PasswordLoginControl;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use ThreeBRS\EnterpriseSecurityBundle\PasswordLoginControl\AbstractPasswordLoginCheckListener;
use ThreeBRS\EnterpriseSecurityBundle\PasswordLoginControl\PasswordLoginPreferenceRepositoryInterface;

#[CoversClass(AbstractPasswordLoginCheckListener::class)]
class AbstractPasswordLoginCheckListenerTest extends TestCase
{
    public function testSubscribesToCheckPassportEventWithHighPriority(): void
    {
        $events = AbstractPasswordLoginCheckListener::getSubscribedEvents();

        self::assertArrayHasKey(CheckPassportEvent::class, $events);
        self::assertSame(['onCheckPassport', 256], $events[CheckPassportEvent::class]);
    }

    public function testIgnoresPassportWithoutPasswordBadge(): void
    {
        // OAuth / passkey / magic-link passports never carry a PasswordCredentials badge —
        // the listener must not interfere with them. Mock's expects(never) asserts the
        // repository was not consulted at all.
        $user = $this->createStub(UserInterface::class);
        $repo = $this->createMock(PasswordLoginPreferenceRepositoryInterface::class);
        $repo->expects(self::never())->method('isPasswordLoginAllowedForUser');

        $passport = new SelfValidatingPassport(new UserBadge('u', static fn () => $user));
        $event = new CheckPassportEvent($this->stubAuthenticator(), $passport);

        $this->listener($repo, true)->onCheckPassport($event);
    }

    public function testIgnoresUnacceptableUser(): void
    {
        // Wrong user type for this listener (admin listener seeing a shop user, or vice versa).
        // Mock's expects(never) asserts the repository was not consulted.
        $user = $this->createStub(UserInterface::class);
        $repo = $this->createMock(PasswordLoginPreferenceRepositoryInterface::class);
        $repo->expects(self::never())->method('isPasswordLoginAllowedForUser');

        $event = $this->eventWithPasswordBadge($user);

        $this->listener($repo, acceptable: false)->onCheckPassport($event);
    }

    public function testIgnoresWhenFeatureDisabled(): void
    {
        // Feature toggled off for the scope — existing per-user preferences must be
        // ignored, so the repository is never consulted and no exception is thrown.
        $user = $this->createStub(UserInterface::class);
        $repo = $this->createMock(PasswordLoginPreferenceRepositoryInterface::class);
        $repo->expects(self::never())->method('isPasswordLoginAllowedForUser');

        $event = $this->eventWithPasswordBadge($user);

        $this->listener($repo, acceptable: true, featureEnabled: false)->onCheckPassport($event);
    }

    public function testAllowsPasswordLoginWhenPreferenceAllowed(): void
    {
        // Mock's expects(once) asserts the repository WAS consulted and the listener
        // did not throw on its `true` answer.
        $user = $this->createStub(UserInterface::class);
        $repo = $this->createMock(PasswordLoginPreferenceRepositoryInterface::class);
        $repo->expects(self::once())
            ->method('isPasswordLoginAllowedForUser')
            ->with($user)
            ->willReturn(true);

        $event = $this->eventWithPasswordBadge($user);

        $this->listener($repo, true)->onCheckPassport($event);
    }

    public function testThrowsWhenPasswordLoginDisabledForUser(): void
    {
        $user = $this->createStub(UserInterface::class);
        $repo = $this->createStub(PasswordLoginPreferenceRepositoryInterface::class);
        $repo->method('isPasswordLoginAllowedForUser')->willReturn(false);

        $event = $this->eventWithPasswordBadge($user);

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('three_brs.password_login_control.disabled_for_user');

        $this->listener($repo, true)->onCheckPassport($event);
    }

    protected function listener(
        PasswordLoginPreferenceRepositoryInterface $repository,
        bool $acceptable,
        bool $featureEnabled = true,
    ): AbstractPasswordLoginCheckListener {
        return new class($repository, $acceptable, $featureEnabled) extends AbstractPasswordLoginCheckListener {
            public function __construct(
                PasswordLoginPreferenceRepositoryInterface $repository,
                private bool $acceptable,
                private bool $featureEnabled,
            ) {
                parent::__construct($repository);
            }

            protected function isFeatureEnabled(): bool
            {
                return $this->featureEnabled;
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptable;
            }

            protected function getErrorMessageKey(): string
            {
                return 'three_brs.password_login_control.disabled_for_user';
            }
        };
    }

    protected function eventWithPasswordBadge(UserInterface $user): CheckPassportEvent
    {
        $passport = new Passport(
            new UserBadge('u', static fn () => $user),
            new PasswordCredentials('plain'),
        );

        return new CheckPassportEvent($this->stubAuthenticator(), $passport);
    }

    protected function stubAuthenticator(): AuthenticatorInterface
    {
        return new class() implements AuthenticatorInterface {
            public function supports(Request $request): ?bool
            {
                return null;
            }

            public function authenticate(Request $request): Passport
            {
                throw new \LogicException('not used');
            }

            public function createToken(Passport $passport, string $firewallName): TokenInterface
            {
                throw new \LogicException('not used');
            }

            public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
            {
                return null;
            }

            public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
            {
                return null;
            }
        };
    }
}
