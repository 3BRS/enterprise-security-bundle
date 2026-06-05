<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\IpWhitelist;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\IpWhitelist\CidrMatcher;

#[CoversClass(CidrMatcher::class)]
class CidrMatcherTest extends TestCase
{
    public function testReturnsFalseWhenIpIsEmpty(): void
    {
        $matcher = new CidrMatcher();

        self::assertFalse($matcher->matchesAny('', ['10.0.0.0/24']));
    }

    public function testReturnsFalseWhenCidrListIsEmpty(): void
    {
        $matcher = new CidrMatcher();

        self::assertFalse($matcher->matchesAny('10.0.0.5', []));
    }

    public function testMatchesIpInCidrRange(): void
    {
        $matcher = new CidrMatcher();

        self::assertTrue($matcher->matchesAny('10.0.0.5', ['10.0.0.0/24']));
    }

    public function testDoesNotMatchIpOutsideCidrRange(): void
    {
        $matcher = new CidrMatcher();

        self::assertFalse($matcher->matchesAny('192.168.1.1', ['10.0.0.0/24']));
    }

    public function testMatchesAgainstAnyCidrInList(): void
    {
        $matcher = new CidrMatcher();

        self::assertTrue($matcher->matchesAny('192.168.1.10', ['10.0.0.0/24', '192.168.0.0/16']));
    }

    public function testMatchesExactIpv4(): void
    {
        $matcher = new CidrMatcher();

        self::assertTrue($matcher->matchesAny('203.0.113.7', ['203.0.113.7']));
    }

    public function testMatchesIpv6CidrRange(): void
    {
        $matcher = new CidrMatcher();

        self::assertTrue($matcher->matchesAny('2001:db8::1', ['2001:db8::/32']));
    }
}
