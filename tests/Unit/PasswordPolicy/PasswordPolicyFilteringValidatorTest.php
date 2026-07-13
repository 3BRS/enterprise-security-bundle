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
    /**
     * The host application's own wording for "password too short" — the bundle knows no such key.
     */
    private const APP_PASSWORD_MIN = 'app.user.password.min';

    private ValidatorInterface $inner;

    private PasswordPolicyFilteringValidator $filteringValidator;

    protected function setUp(): void
    {
        $this->inner = $this->createStub(ValidatorInterface::class);
        $this->filteringValidator = new PasswordPolicyFilteringValidator($this->inner, [self::APP_PASSWORD_MIN]);
    }

    public function testKeepsTheApplicationsMessageWhenItWasNotDeclaredRedundant(): void
    {
        // Nothing is filtered by template unless the application names its own key: the bundle ships
        // no knowledge of any framework's message catalogue.
        $unconfigured = new PasswordPolicyFilteringValidator($this->inner);

        $this->inner->method('validate')->willReturn(new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]));

        self::assertCount(2, $unconfigured->validate('abc', null, null));
    }

    public function testPassesThroughViolationsWhenNoPasswordPolicyViolationIsPresent(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(1, $result);
        self::assertSame(self::APP_PASSWORD_MIN, $result->get(0)->getMessageTemplate());
    }

    public function testRemovesARedundantMessageWhenPasswordPolicyViolationIsPresentOnSamePath(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(1, $result);
        self::assertSame('three_brs.password_policy.min_length', $result->get(0)->getMessageTemplate());
    }

    public function testKeepsARedundantMessageWhenPasswordPolicyViolationIsOnDifferentPath(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'otherField'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(2, $result);
    }

    public function testDoesNotFilterAMessageThatWasNotDeclaredRedundant(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation('app.user.password.max', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(2, $result);
    }

    public function testKeepsAllOtherViolationsIntact(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
            $this->createViolation('three_brs.password_policy.min_length', 'plainPassword'),
            $this->createViolation('three_brs.password_policy.require_uppercase', 'plainPassword'),
            $this->createViolation('app.user.email.not_blank', 'email'),
        ]);

        $this->inner->method('validate')->willReturn($violations);

        $result = $this->filteringValidator->validate('abc', null, null);

        self::assertCount(3, $result);
        $templates = array_map(fn ($v) => $v->getMessageTemplate(), iterator_to_array($result));
        self::assertNotContains(self::APP_PASSWORD_MIN, $templates);
        self::assertContains('three_brs.password_policy.min_length', $templates);
        self::assertContains('three_brs.password_policy.require_uppercase', $templates);
        self::assertContains('app.user.email.not_blank', $templates);
    }

    public function testAlsoFiltersOnValidateProperty(): void
    {
        $violations = new ConstraintViolationList([
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
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
            $this->createViolation(self::APP_PASSWORD_MIN, 'plainPassword'),
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
