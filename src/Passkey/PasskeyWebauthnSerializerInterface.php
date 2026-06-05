<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

interface PasskeyWebauthnSerializerInterface
{
    public function serialize(object $data): string;

    /**
     * @template T of object
     *
     * @param class-string<T> $type
     *
     * @return T
     */
    public function deserialize(string $payload, string $type): object;

    /**
     * @template T of object
     *
     * @param array<string, mixed> $data
     * @param class-string<T> $type
     *
     * @return T
     */
    public function denormalize(array $data, string $type): object;

    /**
     * @return array<string, mixed>
     */
    public function normalize(object $data): array;
}
