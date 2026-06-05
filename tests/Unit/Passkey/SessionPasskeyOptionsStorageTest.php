<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Passkey;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\SessionPasskeyOptionsStorage;

#[CoversClass(SessionPasskeyOptionsStorage::class)]
class SessionPasskeyOptionsStorageTest extends TestCase
{
    public function testStoreAndConsumeRoundTrip(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $requestStack = $this->createStub(RequestStack::class);
        $requestStack->method('getSession')->willReturn($session);

        $storage = new SessionPasskeyOptionsStorage($requestStack);

        $storage->store('key', 'serialized-options');
        self::assertSame('serialized-options', $storage->consume('key'));
        self::assertNull($storage->consume('key'), 'Consume should clear the value.');
    }

    public function testConsumeReturnsNullWhenAbsent(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $requestStack = $this->createStub(RequestStack::class);
        $requestStack->method('getSession')->willReturn($session);

        $storage = new SessionPasskeyOptionsStorage($requestStack);

        self::assertNull($storage->consume('missing'));
    }
}
