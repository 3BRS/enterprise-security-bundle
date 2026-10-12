<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Validator\Constraint;

use Symfony\Component\Validator\Attribute\HasNamedArguments;
use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
class CidrList extends Constraint
{
    public string $invalidMessage = 'three_brs.ip_whitelist.invalid_cidr';

    public string $duplicateMessage = 'three_brs.ip_whitelist.duplicate_cidr';

    /**
     * Options come from named arguments or, as before Symfony 8, from an options array.
     *
     * @param array{invalidMessage?: string, duplicateMessage?: string, groups?: list<string>, payload?: mixed}|null $options
     * @param list<string>|null $groups
     */
    #[HasNamedArguments]
    public function __construct(
        ?array $options = null,
        ?string $invalidMessage = null,
        ?string $duplicateMessage = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups ?? $options['groups'] ?? null, $payload ?? $options['payload'] ?? null);

        $this->invalidMessage = $invalidMessage ?? $options['invalidMessage'] ?? $this->invalidMessage;
        $this->duplicateMessage = $duplicateMessage ?? $options['duplicateMessage'] ?? $this->duplicateMessage;
    }

    public function validatedBy(): string
    {
        return 'three_brs.validator.cidr_list';
    }
}
