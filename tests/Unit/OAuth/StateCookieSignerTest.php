<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSigner;

#[CoversClass(StateCookieSigner::class)]
class StateCookieSignerTest extends TestCase
{
    public function testEncodeThenDecodeRoundTripsThePayload(): void
    {
        $signer = new StateCookieSigner('secret');
        $payload = [
            'state' => 'abc',
            'intent' => 'link',
            'user' => 'user@example.com',
        ];

        self::assertSame($payload, $signer->decode($signer->encode($payload)));
    }

    public function testDecodeRejectsAnUnsignedValue(): void
    {
        // A plain JSON cookie — exactly what an attacker would set via curl if signing were not
        // enforced.
        $unsigned = (string) json_encode([
            'state' => 'abc',
            'intent' => 'link',
            'user' => 'victim',
        ]);

        self::assertNull((new StateCookieSigner('secret'))->decode($unsigned));
    }

    public function testDecodeRejectsAValueSignedWithAnotherSecret(): void
    {
        $forged = (new StateCookieSigner('attacker-secret'))
            ->encode([
                'state' => 'abc',
                'intent' => 'link',
                'user' => 'victim',
            ]);

        self::assertNull((new StateCookieSigner('real-secret'))->decode($forged));
    }

    public function testDecodeRejectsATamperedBodyKeptWithTheOriginalSignature(): void
    {
        $signer = new StateCookieSigner('secret');
        [, $signature] = explode('.', $signer->encode([
            'user' => 'me',
        ]), 2);

        $tamperedBody = rtrim(strtr(base64_encode((string) json_encode([
            'user' => 'victim',
        ])), '+/', '-_'), '=');

        self::assertNull($signer->decode($tamperedBody . '.' . $signature));
    }

    public function testDecodeRejectsMalformedValues(): void
    {
        $signer = new StateCookieSigner('secret');

        self::assertNull($signer->decode(''));
        self::assertNull($signer->decode('no-separator'));
        self::assertNull($signer->decode('.signature-only'));
    }
}
