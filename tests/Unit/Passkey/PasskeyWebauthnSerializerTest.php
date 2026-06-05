<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Passkey;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializer;
use Webauthn\PublicKeyCredentialRpEntity;

#[CoversClass(PasskeyWebauthnSerializer::class)]
class PasskeyWebauthnSerializerTest extends TestCase
{
    public function testSerializeProducesJsonString(): void
    {
        $serializer = new PasskeyWebauthnSerializer();

        $json = $serializer->serialize(PublicKeyCredentialRpEntity::create('Example', 'example.test'));

        self::assertJson($json);
        self::assertStringContainsString('"name":"Example"', $json);
        self::assertStringContainsString('"id":"example.test"', $json);
    }

    public function testNormalizeReturnsAssociativeArray(): void
    {
        $serializer = new PasskeyWebauthnSerializer();

        $data = $serializer->normalize(PublicKeyCredentialRpEntity::create('Example', 'example.test'));

        self::assertSame('Example', $data['name']);
        self::assertSame('example.test', $data['id']);
    }

    public function testDeserializeRoundtripPreservesValues(): void
    {
        $serializer = new PasskeyWebauthnSerializer();
        $original = PublicKeyCredentialRpEntity::create('Example', 'example.test');

        $json = $serializer->serialize($original);
        $decoded = $serializer->deserialize($json, PublicKeyCredentialRpEntity::class);

        self::assertSame('Example', $decoded->name);
        self::assertSame('example.test', $decoded->id);
    }

    public function testDenormalizeFromArray(): void
    {
        $serializer = new PasskeyWebauthnSerializer();

        $entity = $serializer->denormalize(
            [
                'name' => 'Example',
                'id' => 'example.test',
            ],
            PublicKeyCredentialRpEntity::class,
        );

        self::assertSame('Example', $entity->name);
        self::assertSame('example.test', $entity->id);
    }
}
