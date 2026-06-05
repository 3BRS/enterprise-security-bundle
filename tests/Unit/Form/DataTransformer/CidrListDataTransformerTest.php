<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Form\DataTransformer;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Form\DataTransformer\CidrListDataTransformer;

#[CoversClass(CidrListDataTransformer::class)]
class CidrListDataTransformerTest extends TestCase
{
    public function testTransformJoinsListWithNewlines(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame("10.0.0.0/8\n192.168.1.1", $transformer->transform(['10.0.0.0/8', '192.168.1.1']));
    }

    public function testTransformReturnsEmptyStringForNonArray(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame('', $transformer->transform(null));
        self::assertSame('', $transformer->transform('not-an-array'));
    }

    public function testTransformDropsEmptyItems(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame("10.0.0.0/8\n::1", $transformer->transform(['10.0.0.0/8', '', '::1']));
    }

    public function testReverseTransformSplitsOnLineBreaks(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame(
            ['10.0.0.0/8', '192.168.1.1', '::1'],
            $transformer->reverseTransform("10.0.0.0/8\r\n192.168.1.1\n::1"),
        );
    }

    public function testReverseTransformTrimsAndDropsBlankLines(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame(
            ['10.0.0.0/8', '192.168.1.1'],
            $transformer->reverseTransform("  10.0.0.0/8  \n\n   \n 192.168.1.1 \n"),
        );
    }

    public function testReverseTransformReturnsEmptyForNonString(): void
    {
        $transformer = new CidrListDataTransformer();

        self::assertSame([], $transformer->reverseTransform(null));
        self::assertSame([], $transformer->reverseTransform(''));
        self::assertSame([], $transformer->reverseTransform(42));
    }
}
