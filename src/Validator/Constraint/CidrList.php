<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Validator\Constraint;

use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
class CidrList extends Constraint
{
    public string $invalidMessage = 'three_brs.ip_whitelist.invalid_cidr';

    public string $duplicateMessage = 'three_brs.ip_whitelist.duplicate_cidr';

    public function validatedBy(): string
    {
        return 'three_brs.validator.cidr_list';
    }
}
