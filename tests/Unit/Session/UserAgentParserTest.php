<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Session\UserAgentParser;

#[CoversClass(UserAgentParser::class)]
class UserAgentParserTest extends TestCase
{
    public function testReturnsNullValuesForEmptyInput(): void
    {
        $parser = new UserAgentParser();

        $info = $parser->parse(null);
        self::assertNull($info->browser);
        self::assertNull($info->operatingSystem);
        self::assertNull($info->deviceType);

        $info = $parser->parse('');
        self::assertNull($info->browser);
    }

    public function testParsesChromeOnMac(): void
    {
        $parser = new UserAgentParser();
        $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        $info = $parser->parse($ua);

        self::assertSame('Chrome', $info->browser);
        self::assertSame('Mac', $info->operatingSystem);
    }

    public function testParsesUnknownGarbageGracefully(): void
    {
        $parser = new UserAgentParser();

        // matomo may either resolve unknown UAs to null or to a placeholder
        // string ('UNK'). Either is acceptable; the contract here is "no
        // exception thrown, returns a populated DTO".
        $info = $parser->parse('not-a-real-user-agent-string');

        self::assertTrue($info->browser === null || is_string($info->browser));
        self::assertTrue($info->operatingSystem === null || is_string($info->operatingSystem));
    }
}
