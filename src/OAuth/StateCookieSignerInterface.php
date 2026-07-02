<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

interface StateCookieSignerInterface
{
    /**
     * Encodes the payload into a signed, tamper-evident cookie value.
     *
     * @param array<string, mixed> $payload
     */
    public function encode(array $payload): string;

    /**
     * Decodes a signed cookie value, returning the payload only if the signature is present and
     * matches. Returns null for a missing, malformed, tampered, or forged value — so the caller
     * must never trust an unverified cookie.
     *
     * @return array<string, mixed>|null
     */
    public function decode(string $raw): ?array;
}
