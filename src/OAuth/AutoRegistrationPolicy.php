<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

class AutoRegistrationPolicy implements AutoRegistrationPolicyInterface
{
    public function canAutoRegister(OAuthUserInfoInterface $info, ?array $allowedEmailDomains): bool
    {
        $email = $info->getEmail();
        if ($email === null || $email === '') {
            return false;
        }

        if ($info->isEmailVerified() === false) {
            return false;
        }

        if ($allowedEmailDomains === null) {
            return true;
        }

        if ($allowedEmailDomains === []) {
            return false;
        }

        $atPos = strrpos($email, '@');
        if ($atPos === false) {
            return false;
        }

        $domain = strtolower(substr($email, $atPos + 1));
        $normalized = array_map('strtolower', $allowedEmailDomains);

        return in_array($domain, $normalized, true);
    }
}
