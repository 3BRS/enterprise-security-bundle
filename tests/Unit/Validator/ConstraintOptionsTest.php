<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Mapping\ClassMetadata;
use Symfony\Component\Validator\Mapping\Loader\XmlFileLoader;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Validator\Fixture\ConstraintOptionsSubject;
use ThreeBRS\EnterpriseSecurityBundle\PasswordHistory\Constraint\PasswordHistory;
use ThreeBRS\EnterpriseSecurityBundle\PasswordPolicy\Constraint\PasswordPolicy;
use ThreeBRS\EnterpriseSecurityBundle\Validator\Constraint\CidrList;

#[CoversClass(PasswordPolicy::class)]
#[CoversClass(PasswordHistory::class)]
#[CoversClass(CidrList::class)]
class ConstraintOptionsTest extends TestCase
{
    public function testDefaultsApplyWithoutOptions(): void
    {
        $policy = new PasswordPolicy();

        self::assertSame('customer', $policy->policyGroup);
        self::assertSame('three_brs.password_policy.min_length', $policy->minLengthMessage);
        self::assertSame([Constraint::DEFAULT_GROUP], $policy->groups);
        self::assertSame('three_brs.password_history.reused', (new PasswordHistory())->message);
        self::assertSame('three_brs.ip_whitelist.invalid_cidr', (new CidrList())->invalidMessage);
    }

    public function testNamedArgumentsConfigureTheConstraints(): void
    {
        $policy = new PasswordPolicy(policyGroup: 'admin', minLengthMessage: 'min', groups: ['sylius']);
        self::assertSame('admin', $policy->policyGroup);
        self::assertSame('min', $policy->minLengthMessage);
        self::assertSame(['sylius'], $policy->groups);

        $history = new PasswordHistory(message: 'reused', groups: ['sylius']);
        self::assertSame('reused', $history->message);
        self::assertSame(['sylius'], $history->groups);

        $cidrList = new CidrList(invalidMessage: 'invalid', duplicateMessage: 'duplicate');
        self::assertSame('invalid', $cidrList->invalidMessage);
        self::assertSame('duplicate', $cidrList->duplicateMessage);
    }

    #[IgnoreDeprecations]
    public function testOptionsArrayConfiguresTheConstraints(): void
    {
        $policy = new PasswordPolicy([
            'policyGroup' => 'admin',
            'groups' => ['sylius'],
        ]);
        self::assertSame('admin', $policy->policyGroup);
        self::assertSame(['sylius'], $policy->groups);

        self::assertSame('reused', (new PasswordHistory([
            'message' => 'reused',
        ]))->message);
        self::assertSame('duplicate', (new CidrList([
            'duplicateMessage' => 'duplicate',
        ]))->duplicateMessage);
    }

    public function testXmlMappingConfiguresTheConstraints(): void
    {
        $metadata = new ClassMetadata(ConstraintOptionsSubject::class);
        (new XmlFileLoader(__DIR__ . '/Fixture/constraint-options.xml'))->loadClassMetadata($metadata);

        [$policy, $history] = $metadata->getPropertyMetadata('password')[0]->getConstraints();
        self::assertInstanceOf(PasswordPolicy::class, $policy);
        self::assertSame('admin', $policy->policyGroup);
        self::assertSame(['sylius'], $policy->groups);
        self::assertInstanceOf(PasswordHistory::class, $history);
        self::assertSame('reused', $history->message);

        [$cidrList] = $metadata->getPropertyMetadata('cidrs')[0]->getConstraints();
        self::assertInstanceOf(CidrList::class, $cidrList);
        self::assertSame('invalid', $cidrList->invalidMessage);
    }
}
