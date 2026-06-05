<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;
use Symfony\Component\Validator\Exception\UnexpectedValueException;
use ThreeBRS\EnterpriseSecurityBundle\Validator\Constraint\CidrList;

class CidrListValidator extends ConstraintValidator implements CidrListValidatorInterface
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (! $constraint instanceof CidrList) {
            throw new UnexpectedTypeException($constraint, CidrList::class);
        }

        if ($value === null || $value === []) {
            return;
        }

        if (! is_array($value)) {
            throw new UnexpectedValueException($value, 'array');
        }

        $seen = [];
        foreach ($value as $entry) {
            if (! is_string($entry) || $entry === '') {
                continue;
            }

            if (! $this->isValidCidrOrIp($entry)) {
                $this->context->buildViolation($constraint->invalidMessage)
                    ->setParameter('{{ value }}', $entry)
                    ->addViolation()
                ;

                continue;
            }

            $normalized = strtolower($entry);
            if (isset($seen[$normalized])) {
                $this->context->buildViolation($constraint->duplicateMessage)
                    ->setParameter('{{ value }}', $entry)
                    ->addViolation()
                ;

                continue;
            }

            $seen[$normalized] = true;
        }
    }

    protected function isValidCidrOrIp(string $value): bool
    {
        if (! str_contains($value, '/')) {
            return filter_var($value, \FILTER_VALIDATE_IP) !== false;
        }

        $parts = explode('/', $value, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$address, $prefixStr] = $parts;

        if (! ctype_digit($prefixStr)) {
            return false;
        }

        $prefix = (int) $prefixStr;

        if (filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4) !== false) {
            return $prefix >= 0 && $prefix <= 32;
        }

        if (filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) !== false) {
            return $prefix >= 0 && $prefix <= 128;
        }

        return false;
    }
}
