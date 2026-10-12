<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\Constraint;

use Symfony\Component\Validator\Attribute\HasNamedArguments;
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

    /**
     * Options come from named arguments or, as before Symfony 8, from an options array.
     *
     * @param array{policyGroup?: string, minLengthMessage?: string, maxLengthMessage?: string, requireUppercaseMessage?: string, requireLowercaseMessage?: string, requireNumbersMessage?: string, requireSpecialCharactersMessage?: string, groups?: list<string>, payload?: mixed}|null $options
     * @param list<string>|null $groups
     */
    #[HasNamedArguments]
    public function __construct(
        ?array $options = null,
        ?string $policyGroup = null,
        ?string $minLengthMessage = null,
        ?string $maxLengthMessage = null,
        ?string $requireUppercaseMessage = null,
        ?string $requireLowercaseMessage = null,
        ?string $requireNumbersMessage = null,
        ?string $requireSpecialCharactersMessage = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups ?? $options['groups'] ?? null, $payload ?? $options['payload'] ?? null);

        $this->policyGroup = $policyGroup ?? $options['policyGroup'] ?? $this->policyGroup;
        $this->minLengthMessage = $minLengthMessage ?? $options['minLengthMessage'] ?? $this->minLengthMessage;
        $this->maxLengthMessage = $maxLengthMessage ?? $options['maxLengthMessage'] ?? $this->maxLengthMessage;
        $this->requireUppercaseMessage = $requireUppercaseMessage ?? $options['requireUppercaseMessage'] ?? $this->requireUppercaseMessage;
        $this->requireLowercaseMessage = $requireLowercaseMessage ?? $options['requireLowercaseMessage'] ?? $this->requireLowercaseMessage;
        $this->requireNumbersMessage = $requireNumbersMessage ?? $options['requireNumbersMessage'] ?? $this->requireNumbersMessage;
        $this->requireSpecialCharactersMessage = $requireSpecialCharactersMessage ?? $options['requireSpecialCharactersMessage'] ?? $this->requireSpecialCharactersMessage;
    }

    public function validatedBy(): string
    {
        return 'three_brs.validator.password_policy';
    }
}
