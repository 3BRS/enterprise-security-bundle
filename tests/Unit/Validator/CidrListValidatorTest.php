<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Context\ExecutionContextInterface;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;
use Symfony\Component\Validator\Exception\UnexpectedValueException;
use Symfony\Component\Validator\Violation\ConstraintViolationBuilderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Validator\CidrListValidator;
use ThreeBRS\EnterpriseSecurityBundle\Validator\Constraint\CidrList;

#[CoversClass(CidrListValidator::class)]
class CidrListValidatorTest extends TestCase
{
    private ExecutionContextInterface&MockObject $context;

    private ConstraintViolationBuilderInterface $violationBuilder;

    protected function setUp(): void
    {
        $this->context = $this->createMock(ExecutionContextInterface::class);
        $this->violationBuilder = $this->createStub(ConstraintViolationBuilderInterface::class);
        $this->violationBuilder->method('setParameter')->willReturnSelf();
        $this->violationBuilder->method('addViolation');
    }

    public function testThrowsOnWrongConstraintType(): void
    {
        $this->context->expects(self::never())->method('buildViolation');
        $this->expectException(UnexpectedTypeException::class);

        $this->createValidator()->validate(['10.0.0.0/8'], $this->createStub(Constraint::class));
    }

    public function testSkipsNullValue(): void
    {
        $this->context->expects(self::never())->method('buildViolation');

        $this->createValidator()->validate(null, new CidrList());
    }

    public function testSkipsEmptyArray(): void
    {
        $this->context->expects(self::never())->method('buildViolation');

        $this->createValidator()->validate([], new CidrList());
    }

    public function testThrowsOnNonArray(): void
    {
        $this->context->expects(self::never())->method('buildViolation');
        $this->expectException(UnexpectedValueException::class);

        $this->createValidator()->validate('10.0.0.0/8', new CidrList());
    }

    public function testAcceptsValidIpv4(): void
    {
        $this->context->expects(self::never())->method('buildViolation');

        $this->createValidator()->validate(['192.168.1.1'], new CidrList());
    }

    public function testAcceptsValidIpv4Cidr(): void
    {
        $this->context->expects(self::never())->method('buildViolation');

        $this->createValidator()->validate(['10.0.0.0/8', '192.168.0.0/16'], new CidrList());
    }

    public function testAcceptsValidIpv6Cidr(): void
    {
        $this->context->expects(self::never())->method('buildViolation');

        $this->createValidator()->validate(['2001:db8::/32', '::1'], new CidrList());
    }

    public function testRejectsInvalidEntries(): void
    {
        $this->context->expects(self::exactly(2))
            ->method('buildViolation')
            ->willReturn($this->violationBuilder)
        ;

        $this->createValidator()->validate(['not.an.ip', '10.0.0.0/99'], new CidrList());
    }

    public function testRejectsIpv4PrefixOutOfRange(): void
    {
        $this->context->expects(self::once())
            ->method('buildViolation')
            ->willReturn($this->violationBuilder)
        ;

        $this->createValidator()->validate(['10.0.0.0/33'], new CidrList());
    }

    public function testRejectsIpv6PrefixOutOfRange(): void
    {
        $this->context->expects(self::once())
            ->method('buildViolation')
            ->willReturn($this->violationBuilder)
        ;

        $this->createValidator()->validate(['2001:db8::/129'], new CidrList());
    }

    public function testRejectsDuplicates(): void
    {
        $this->context->expects(self::once())
            ->method('buildViolation')
            ->willReturn($this->violationBuilder)
        ;

        $this->createValidator()->validate(['10.0.0.0/8', '10.0.0.0/8'], new CidrList());
    }

    public function testRejectsCaseInsensitiveDuplicates(): void
    {
        $this->context->expects(self::once())
            ->method('buildViolation')
            ->willReturn($this->violationBuilder)
        ;

        $this->createValidator()->validate(['2001:DB8::/32', '2001:db8::/32'], new CidrList());
    }

    private function createValidator(): CidrListValidator
    {
        $validator = new CidrListValidator();
        $validator->initialize($this->context);

        return $validator;
    }
}
