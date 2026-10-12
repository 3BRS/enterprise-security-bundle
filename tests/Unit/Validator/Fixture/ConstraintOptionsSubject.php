<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Validator\Fixture;

class ConstraintOptionsSubject
{
    public string $password = '';

    /**
     * @var list<string>
     */
    public array $cidrs = [];
}
