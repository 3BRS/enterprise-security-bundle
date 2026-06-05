<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordHistory\Constraint;

use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
class PasswordHistory extends Constraint
{
    public string $message = 'three_brs.password_history.reused';

    public function validatedBy(): string
    {
        return 'three_brs.validator.password_history';
    }
}
