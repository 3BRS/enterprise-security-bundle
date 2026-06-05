<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\PasswordPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\PasswordPolicyFilteringValidator;

#[CoversClass(PasswordPolicyFilteringValidator::class)]
class PasswordPolicyFilteringValidatorTest extends TestCase
{
    private ValidatorInterface $inner;

    private PasswordPolicyFilteringValidator $filteringValidator;

    protected function setUp(): void
    {
        $this->inner = $this->createStub(ValidatorInterface::class);
        $this->filteringValidator = new PasswordPolicyFilteringValidator($this->inner);
    }

    public function testPassesThroughViolationsWhenNoPasswordPolicyViolationIsPresent(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(1, $result);
        self::assertSame('sylius.user.password.min', $result->get(0)->getMessageTemplate());
    }

    public function testRemovesSyliusPasswordMinViolationWhenPasswordPolicyViolationIsPresentOnSamePath(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(1, $result);
        self::assertSame('three_brs.password_policy.min_length', $result->get(0)->getMessageTemplate());
    }

    public function testKeepsSyliusPasswordMinViolationWhenPasswordPolicyViolationIsOnDifferentPath(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'otherField'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(2, $result);
    }

    public function testDoesNotFilterSyliusPasswordMaxViolation(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.max', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(2, $result);
    }

    public function testKeepsAllOtherViolationsIntact(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.require_uppercase', 'plainPassword'),
            $this->createViolation('sylius.user.email.not_blank', 'email'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(3, $result);
        $templates = array_map(fn ($v) => $v->getMessageTemplate(), iterator_to_array($result));
        self::assertNotContains('sylius.user.password.min', $templates);
        self::assertContains('three_brs.password_policy.min_length', $templates);
        self::assertContains('three_brs.password_policy.require_uppercase', $templates);
        self::assertContains('sylius.user.email.not_blank', $templates);
    }

    public function testAlsoFiltersOnValidateProperty(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validateProperty')->willReturn($violations);

        $result = $this->filteringValidator->validateProperty(new \stdClass(), 'plainPassword');

        self::assertCount(1, $result);
        self::assertSame('three_brs.password_policy.min_length', $result->get(0)->getMessageTemplate());
    }

    public function testAlsoFiltersOnValidatePropertyValue(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('sylius.user.password.min', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validatePropertyValue')->willReturn($violations);

        $result = $this->filteringValidator->validatePropertyValue(\stdClass::class, 'plainPassword', 'abc');

        self::assertCount(1, $result);
        self::assertSame('three_brs.password_policy.min_length', $result->get(0)->getMessageTemplate());
    }

    public function testRemovesLengthTooShortViolationByCodeWhenPasswordPolicyViolationIsPresentOnSamePath(): void
    {
        $lengthViolation = new ConstraintViolation(
            message: 'This value is too short.',
            messageTemplate: 'This value is too short.',
            parameters: [],
            root: null,
            propertyPath: 'plainPassword',
            invalidValue: null,
            code: Length::TOO_SHORT_ERROR,
        );

        $violations = new ConstraintViolationList([
            $lengthViolation,
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(1, $result);
        self::assertSame('three_brs.password_policy.min_length', $result->get(0)->getMessageTemplate());
    }

    private function createViolation(string $messageTemplate, string $propertyPath): ConstraintViolation
    {
        return new ConstraintViolation(
            message: $messageTemplate,
            messageTemplate: $messageTemplate,
            parameters: [],
            root: null,
            propertyPath: $propertyPath,
            invalidValue: null,
        );
    }
}
