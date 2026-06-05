<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\AutoRegistrationPolicy;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfoInterface;

#[CoversClass(AutoRegistrationPolicy::class)]
class AutoRegistrationPolicyTest extends TestCase
{
    public function testRejectsWhenEmailMissing(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertFalse($policy->canAutoRegister($this->userInfo(null, true), null));
        self::assertFalse($policy->canAutoRegister($this->userInfo('', true), null));
    }

    public function testRejectsWhenEmailExplicitlyUnverified(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertFalse($policy->canAutoRegister($this->userInfo('user@example.com', false), null));
    }

    public function testAcceptsWithoutDomainCheckWhenAllowedDomainsNull(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertTrue($policy->canAutoRegister($this->userInfo('user@anywhere.test', true), null));
    }

    public function testAcceptsWhenEmailVerifiedIsNull(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertTrue($policy->canAutoRegister($this->userInfo('user@anywhere.test', null), null));
    }

    public function testRejectsWhenAllowedDomainsEmpty(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertFalse($policy->canAutoRegister($this->userInfo('user@example.com', true), []));
    }

    public function testAcceptsWhenEmailDomainMatchesAllowedList(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertTrue($policy->canAutoRegister(
            $this->userInfo('user@Allowed.test', true),
            ['allowed.test', 'other.test'],
        ));
    }

    public function testRejectsWhenEmailDomainNotInAllowedList(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertFalse($policy->canAutoRegister(
            $this->userInfo('user@blocked.test', true),
            ['allowed.test'],
        ));
    }

    public function testDomainComparisonIsCaseInsensitive(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertTrue($policy->canAutoRegister(
            $this->userInfo('user@Mixed.Case.TEST', true),
            ['MIXED.case.test'],
        ));
    }

    public function testRejectsWhenEmailHasNoAtSign(): void
    {
        $policy = new AutoRegistrationPolicy();

        self::assertFalse($policy->canAutoRegister(
            $this->userInfo('not-an-email', true),
            ['example.com'],
        ));
    }

    protected function userInfo(?string $email, ?bool $emailVerified): OAuthUserInfoInterface
    {
        $info = $this->createStub(OAuthUserInfoInterface::class);
        $info->method('getEmail')->willReturn($email);
        $info->method('isEmailVerified')->willReturn($emailVerified);

        return $info;
    }
}
