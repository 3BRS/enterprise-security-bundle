<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy;

class PasswordPolicy implements PasswordPolicyInterface
{
    public function __construct(
        protected int $minLength,
        protected ?int $maxLength,
        protected bool $requireUppercase,
        protected bool $requireLowercase,
        protected bool $requireNumbers,
        protected bool $requireSpecialCharacters,
    ) {
    }

    public function getMinLength(): int
    {
        return $this->minLength;
    }

    public function getMaxLength(): ?int
    {
        return $this->maxLength;
    }

    public function isRequireUppercase(): bool
    {
        return $this->requireUppercase;
    }

    public function isRequireLowercase(): bool
    {
        return $this->requireLowercase;
    }

    public function isRequireNumbers(): bool
    {
        return $this->requireNumbers;
    }

    public function isRequireSpecialCharacters(): bool
    {
        return $this->requireSpecialCharacters;
    }
}
