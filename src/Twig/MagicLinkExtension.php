<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Twig;

use ThreeBRS\EnterpriseSecurityBundle\Settings\FeatureToggleInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class MagicLinkExtension extends AbstractExtension implements MagicLinkExtensionInterface
{
    public function __construct(
        protected FeatureToggleInterface $features,
    ) {
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('three_brs_magic_link_enabled', $this->isEnabled(...)),
        ];
    }

    public function isEnabled(string $group): bool
    {
        $scope = $group === 'admin' ? SettingsScope::ADMIN : SettingsScope::CUSTOMER;

        return $this->features->isEnabled('magic_link', $scope);
    }
}
