<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Twig;

interface SocialProvidersExtensionInterface
{
    /**
     * @return list<string>
     */
    public function getSocialProviderNames(string $group): array;
}
