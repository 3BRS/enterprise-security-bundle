<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Twig;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Settings\FeatureToggleInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;
use ThreeBRS\EnterpriseSecurityBundle\Twig\MagicLinkExtension;
use Twig\TwigFunction;

#[CoversClass(MagicLinkExtension::class)]
class MagicLinkExtensionTest extends TestCase
{
    public function testIsEnabledForAdminScope(): void
    {
        $features = $this->createMock(FeatureToggleInterface::class);
        $features->expects(self::once())
            ->method('isEnabled')
            ->with('magic_link', SettingsScope::ADMIN)
            ->willReturn(true);

        $extension = new MagicLinkExtension($features);

        self::assertTrue($extension->isEnabled('admin'));
    }

    public function testIsEnabledForCustomerScope(): void
    {
        $features = $this->createMock(FeatureToggleInterface::class);
        $features->expects(self::once())
            ->method('isEnabled')
            ->with('magic_link', SettingsScope::CUSTOMER)
            ->willReturn(false);

        $extension = new MagicLinkExtension($features);

        self::assertFalse($extension->isEnabled('customer'));
    }

    public function testGetFunctionsExposesEnabledHelper(): void
    {
        $extension = new MagicLinkExtension($this->createStub(FeatureToggleInterface::class));

        $functions = $extension->getFunctions();

        self::assertCount(1, $functions);
        self::assertInstanceOf(TwigFunction::class, $functions[0]);
        self::assertSame('three_brs_magic_link_enabled', $functions[0]->getName());
    }
}
