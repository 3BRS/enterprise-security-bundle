<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Constraints\GroupSequence;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\ConstraintViolationList;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Context\ExecutionContextInterface;
use Symfony\Component\Validator\Mapping\MetadataInterface;
use Symfony\Component\Validator\Validator\ContextualValidatorInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class PasswordPolicyFilteringValidator implements PasswordPolicyFilteringValidatorInterface
{
    public function __construct(
        protected ValidatorInterface $inner,
    ) {
    }

    public function validate(mixed $value, Constraint|array|null $constraints = null, string|GroupSequence|array|null $groups = null): ConstraintViolationListInterface
    {
        return $this->filter($this->inner->validate($value, $constraints, $groups));
    }

    public function validateProperty(object $object, string $propertyName, string|GroupSequence|array|null $groups = null): ConstraintViolationListInterface
    {
        return $this->filter($this->inner->validateProperty($object, $propertyName, $groups));
    }

    public function validatePropertyValue(object|string $objectOrClass, string $propertyName, mixed $value, string|GroupSequence|array|null $groups = null): ConstraintViolationListInterface
    {
        return $this->filter($this->inner->validatePropertyValue($objectOrClass, $propertyName, $value, $groups));
    }

    public function startContext(): ContextualValidatorInterface
    {
        return $this->inner->startContext();
    }

    public function inContext(ExecutionContextInterface $context): ContextualValidatorInterface
    {
        return $this->inner->inContext($context);
    }

    public function getMetadataFor(mixed $value): MetadataInterface
    {
        return $this->inner->getMetadataFor($value);
    }

    public function hasMetadataFor(mixed $value): bool
    {
        return $this->inner->hasMetadataFor($value);
    }

    protected function filter(ConstraintViolationListInterface $violations): ConstraintViolationListInterface
    {
        $passwordPolicyPaths = [];
        foreach ($violations as $violation) {
            if (str_starts_with($violation->getMessageTemplate(), 'three_brs.password_policy.')) {
                $passwordPolicyPaths[$violation->getPropertyPath()] = true;
            }
        }

        if ($passwordPolicyPaths === []) {
            return $violations;
        }

        $filtered = new ConstraintViolationList();
        foreach ($violations as $violation) {
            if (
                (
                    $violation->getMessageTemplate() === 'sylius.user.password.min' ||
                    $violation->getCode() === Length::TOO_SHORT_ERROR
                ) &&
                isset($passwordPolicyPaths[$violation->getPropertyPath()])
            ) {
                continue;
            }

            $filtered->add($violation);
        }

        return $filtered;
    }
}
