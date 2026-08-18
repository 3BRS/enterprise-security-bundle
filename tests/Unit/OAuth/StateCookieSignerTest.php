<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\OAuth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSigner;

#[CoversClass(StateCookieSigner::class)]
class StateCookieSignerTest extends TestCase
{
    protected const NOW = 1700000000;

    protected const TTL = 600;

    public function testEncodeThenDecodeRoundTripsThePayload(): void
    {
        $signer = $this->signer('secret');
        $payload = [
            'state' => 'abc',
            'intent' => 'link',
            'user' => 'user@example.com',
        ];

        // The expiry the signer stamps in is its own business: it goes in on encode and comes back
        // out on decode, so a caller's payload survives unchanged.
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

        self::assertNull($this->signer('secret')->decode($unsigned));
    }

    public function testDecodeRejectsAValueSignedWithAnotherSecret(): void
    {
        $forged = $this->signer('attacker-secret')
            ->encode([
                'state' => 'abc',
                'intent' => 'link',
                'user' => 'victim',
            ]);

        self::assertNull($this->signer('real-secret')->decode($forged));
    }

    public function testDecodeRejectsATamperedBodyKeptWithTheOriginalSignature(): void
    {
        $signer = $this->signer('secret');
        [, $signature] = explode('.', $signer->encode([
            'user' => 'me',
        ]), 2);

        $tamperedBody = $this->base64Url((string) json_encode([
            'user' => 'victim',
            'exp' => self::NOW + self::TTL,
        ]));

        self::assertNull($signer->decode($tamperedBody . '.' . $signature));
    }

    public function testDecodeRejectsMalformedValues(): void
    {
        $signer = $this->signer('secret');

        self::assertNull($signer->decode(''));
        self::assertNull($signer->decode('no-separator'));
        self::assertNull($signer->decode('.signature-only'));
    }

    public function testDecodeAcceptsAValueOneSecondBeforeItExpires(): void
    {
        $issued = $this->signer('secret', self::NOW)->encode([
            'user' => 'me',
        ]);

        self::assertSame([
            'user' => 'me',
        ], $this->signer('secret', self::NOW + self::TTL - 1)->decode($issued));
    }

    public function testDecodeRejectsAValueThatHasExpired(): void
    {
        // The whole point of the finding this covers: the cookie's own `Expires` attribute is a
        // browser hint, so a captured value replayed by curl must be refused by the signature.
        $issued = $this->signer('secret', self::NOW)->encode([
            'state' => 'abc',
            'intent' => 'link',
            'user' => 'victim',
        ]);

        self::assertNull($this->signer('secret', self::NOW + self::TTL + 1)->decode($issued));
    }

    public function testDecodeRejectsAValueExactlyAtItsExpiry(): void
    {
        $issued = $this->signer('secret', self::NOW)->encode([
            'user' => 'me',
        ]);

        self::assertNull($this->signer('secret', self::NOW + self::TTL)->decode($issued));
    }

    public function testDecodeRejectsAValidlySignedBodyCarryingNoExpiry(): void
    {
        // A value minted before the expiry check existed. It is properly signed, so only the
        // missing `exp` can reject it — and it must, or those keep their unlimited lifetime.
        $signer = $this->signer('secret');
        $body = $this->base64Url((string) json_encode([
            'state' => 'abc',
            'intent' => 'link',
            'user' => 'victim',
        ]));
        $signature = hash_hmac('sha256', $body, 'secret');

        self::assertNull($signer->decode($body . '.' . $signature));
    }

    public function testDecodeRejectsANonIntegerExpiry(): void
    {
        $signer = $this->signer('secret');
        $body = $this->base64Url((string) json_encode([
            'user' => 'victim',
            'exp' => 'never',
        ]));
        $signature = hash_hmac('sha256', $body, 'secret');

        self::assertNull($signer->decode($body . '.' . $signature));
    }

    public function testEncodeOverwritesACallerSuppliedExpiry(): void
    {
        $issued = $this->signer('secret', self::NOW)->encode([
            'user' => 'me',
            'exp' => self::NOW + 86400,
        ]);

        // The caller's day-long expiry must not win over the signer's TTL.
        self::assertNull($this->signer('secret', self::NOW + self::TTL + 1)->decode($issued));
    }

    protected function signer(string $secret, int $now = self::NOW): StateCookieSigner
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable('@' . $now));

        return new StateCookieSigner($secret, $clock, self::TTL);
    }

    protected function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
