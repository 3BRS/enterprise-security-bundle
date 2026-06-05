<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Passkey;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyCeremonyStepManagerFactory;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyValidatorFactory;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;

#[CoversClass(PasskeyValidatorFactory::class)]
class PasskeyValidatorFactoryTest extends TestCase
{
    public function testCreatesAttestationValidator(): void
    {
        $factory = new PasskeyValidatorFactory(new PasskeyCeremonyStepManagerFactory(rpId: 'example.test'));

        self::assertInstanceOf(AuthenticatorAttestationResponseValidator::class, $factory->createAttestationValidator());
    }

    public function testCreatesAssertionValidator(): void
    {
        $factory = new PasskeyValidatorFactory(new PasskeyCeremonyStepManagerFactory(rpId: 'example.test'));

        self::assertInstanceOf(AuthenticatorAssertionResponseValidator::class, $factory->createAssertionValidator());
    }
}
