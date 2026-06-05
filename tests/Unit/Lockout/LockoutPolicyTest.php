<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Lockout;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockoutPolicy;

#[CoversClass(LockoutPolicy::class)]
class LockoutPolicyTest extends TestCase
{
    public function testExposesConstructorValues(): void
    {
        $policy = new LockoutPolicy(enabled: true, maxAttempts: 5, autoUnlockAfter: 600);

        self::assertTrue($policy->isEnabled());
        self::assertSame(5, $policy->getMaxAttempts());
        self::assertSame(600, $policy->getAutoUnlockAfter());
    }

    public function testCanBeDisabledWithNullAutoUnlock(): void
    {
        $policy = new LockoutPolicy(enabled: false, maxAttempts: 3, autoUnlockAfter: null);

        self::assertFalse($policy->isEnabled());
        self::assertSame(3, $policy->getMaxAttempts());
        self::assertNull($policy->getAutoUnlockAfter());
    }
}
