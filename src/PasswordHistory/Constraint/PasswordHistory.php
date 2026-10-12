<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordHistory\Constraint;

use Symfony\Component\Validator\Attribute\HasNamedArguments;
use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
class PasswordHistory extends Constraint
{
    public string $message = 'three_brs.password_history.reused';

    /**
     * Options come from named arguments or, as before Symfony 8, from an options array.
     *
     * @param array{message?: string, groups?: list<string>, payload?: mixed}|null $options
     * @param list<string>|null $groups
     */
    #[HasNamedArguments]
    public function __construct(
        ?array $options = null,
        ?string $message = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups ?? $options['groups'] ?? null, $payload ?? $options['payload'] ?? null);

        $this->message = $message ?? $options['message'] ?? $this->message;
    }

    public function validatedBy(): string
    {
        return 'three_brs.validator.password_history';
    }
}
