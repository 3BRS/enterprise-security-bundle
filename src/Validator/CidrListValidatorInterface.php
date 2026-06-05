<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Validator;

use Symfony\Component\Validator\Constraint;

interface CidrListValidatorInterface
{
    public function validate(mixed $value, Constraint $constraint): void;
}
