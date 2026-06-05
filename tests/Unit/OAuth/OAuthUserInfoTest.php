<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\OAuthUserInfo;

#[CoversClass(OAuthUserInfo::class)]
class OAuthUserInfoTest extends TestCase
{
    public function testAccessors(): void
    {
        $info = new OAuthUserInfo('google', '12345', 'a@b.c', 'Alice', 'Cooper');

        self::assertSame('google', $info->getProvider());
        self::assertSame('12345', $info->getProviderUserId());
        self::assertSame('a@b.c', $info->getEmail());
        self::assertSame('Alice', $info->getFirstName());
        self::assertSame('Cooper', $info->getLastName());
    }

    public function testOptionalFieldsCanBeNull(): void
    {
        $info = new OAuthUserInfo('apple', 'uid', null);

        self::assertNull($info->getEmail());
        self::assertNull($info->getFirstName());
        self::assertNull($info->getLastName());
    }
}
