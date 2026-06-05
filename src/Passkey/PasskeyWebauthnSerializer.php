<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

class PasskeyWebauthnSerializer implements PasskeyWebauthnSerializerInterface
{
    protected ?SerializerInterface $serializer = null;

    public function serialize(object $data): string
    {
        return $this->getSerializer()->serialize($data, 'json');
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $type
     *
     * @return T
     */
    public function deserialize(string $payload, string $type): object
    {
        /** @var T $object */
        $object = $this->getSerializer()->deserialize($payload, $type, 'json');

        return $object;
    }

    /**
     * @template T of object
     *
     * @param array<string, mixed> $data
     * @param class-string<T> $type
     *
     * @return T
     */
    public function denormalize(array $data, string $type): object
    {
        return $this->deserialize((string) json_encode($data), $type);
    }

    public function normalize(object $data): array
    {
        /** @var array<string, mixed> $decoded */
        $decoded = (array) json_decode($this->serialize($data), true);

        return $decoded;
    }

    protected function getSerializer(): SerializerInterface
    {
        if ($this->serializer === null) {
            $this->serializer = (new WebauthnSerializerFactory(
                AttestationStatementSupportManager::create(),
            ))->create();
        }

        return $this->serializer;
    }
}
