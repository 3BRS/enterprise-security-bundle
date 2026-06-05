<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Passkey;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyCeremonyStepManagerFactory;
use Webauthn\CeremonyStep\CeremonyStepManager;

#[CoversClass(PasskeyCeremonyStepManagerFactory::class)]
class PasskeyCeremonyStepManagerFactoryTest extends TestCase
{
    public function testCreatesCeremonyStepManagerForCreation(): void
    {
        $factory = new PasskeyCeremonyStepManagerFactory(rpId: 'example.test');

        self::assertInstanceOf(CeremonyStepManager::class, $factory->createForCreationCeremony());
    }

    public function testCreatesCeremonyStepManagerForRequest(): void
    {
        $factory = new PasskeyCeremonyStepManagerFactory(rpId: 'example.test');

        self::assertInstanceOf(CeremonyStepManager::class, $factory->createForRequestCeremony());
    }

    public function testProducesDistinctManagersPerCall(): void
    {
        $factory = new PasskeyCeremonyStepManagerFactory(rpId: 'example.test');

        self::assertNotSame($factory->createForCreationCeremony(), $factory->createForCreationCeremony());
    }
}
