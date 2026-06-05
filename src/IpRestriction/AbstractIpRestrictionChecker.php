<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\IpRestriction;

use ThreeBRS\EnterpriseSecurityBundle\IpWhitelist\CidrMatcherInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

/**
 * Generic orchestration for a global IP restriction feature (whitelist OR
 * blacklist). Reads the global CIDR list + feature toggle from settings and
 * matches an IP against it via the bundle's `CidrMatcher`. Subclass binds the
 * settings key + scope; matching semantics (allow vs deny) are decided by the
 * caller (a "match" means "this CIDR list covers the IP", interpretation is
 * scope-specific).
 */
abstract class AbstractIpRestrictionChecker
{
    public function __construct(
        protected SettingsProviderInterface $settingsProvider,
        protected CidrMatcherInterface $cidrMatcher,
    ) {
    }

    public function isFeatureEnabled(): bool
    {
        return $this->settingsProvider->getBool($this->getSettingsKey() . '.enabled', $this->getScope());
    }

    public function matchesGlobal(string $ip): bool
    {
        return $this->cidrMatcher->matchesAny($ip, $this->getGlobalCidrs());
    }

    /**
     * @return list<string>
     */
    public function getGlobalCidrs(): array
    {
        $value = $this->settingsProvider->get($this->getSettingsKey() . '.global_cidrs', $this->getScope());
        if (! is_array($value)) {
            return [];
        }

        $cidrs = [];
        foreach ($value as $cidr) {
            if (is_string($cidr) && $cidr !== '') {
                $cidrs[] = $cidr;
            }
        }

        return $cidrs;
    }

    /**
     * Settings key prefix (e.g. `ip_whitelist`, `ip_blacklist`) for the
     * `.enabled` and `.global_cidrs` lookups.
     */
    abstract protected function getSettingsKey(): string;

    abstract protected function getScope(): SettingsScope;
}
