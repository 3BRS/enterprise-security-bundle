<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\Constraint;

use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
class PasswordPolicy extends Constraint
{
    public string $policyGroup = 'customer';

    public string $minLengthMessage = 'three_brs.password_policy.min_length';

    public string $maxLengthMessage = 'three_brs.password_policy.max_length';

    public string $requireUppercaseMessage = 'three_brs.password_policy.require_uppercase';

    public string $requireLowercaseMessage = 'three_brs.password_policy.require_lowercase';

    public string $requireNumbersMessage = 'three_brs.password_policy.require_numbers';

    public string $requireSpecialCharactersMessage = 'three_brs.password_policy.require_special_characters';

    public function validatedBy(): string
    {
        return 'three_brs.validator.password_policy';
    }
}
