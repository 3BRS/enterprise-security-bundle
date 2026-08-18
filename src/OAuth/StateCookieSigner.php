<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

use Psr\Clock\ClockInterface;

/**
 * Signs the OAuth state cookie (used for cross-site `form_post` callbacks, e.g. Apple) with an
 * HMAC so its contents — crucially the link-initiating user identifier — cannot be forged or
 * altered by the client.
 *
 * The cookie's HttpOnly / Secure / SameSite flags only constrain a victim's *browser*; they do
 * nothing against a request an attacker crafts directly (curl), where the attacker controls
 * every cookie. The payload must therefore be authenticated, not merely transported securely:
 * without a signature an attacker could set `user` to a victim and have the callback log in and
 * link as that victim.
 *
 * The signature also carries its own expiry. The cookie's `Expires` attribute is a hint to a
 * cooperating browser and nothing more — an attacker replaying a captured value sends whatever
 * cookies they like, so without `exp` inside the signed body the value stays valid forever. That
 * matters because a `link` cookie names a user the callback will sign in: any copy that outlives
 * the browser's ten-minute window (an exported HAR, a proxy or WAF log, a captured request in an
 * error report) would otherwise remain a working sign-in for that account indefinitely, unaffected
 * by logout, a password change or "revoke all sessions". This class is the authority on lifetime;
 * the cookie attribute only saves the browser a pointless round-trip.
 */
class StateCookieSigner implements StateCookieSignerInterface
{
    protected const SEPARATOR = '.';

    /**
     * Reserved payload key holding the expiry timestamp. Added by {@see encode()} and consumed by
     * {@see decode()}, so a payload survives the round-trip unchanged — callers neither set it nor
     * see it. A caller-supplied `exp` is overwritten.
     */
    protected const EXPIRY_KEY = 'exp';

    public function __construct(
        protected string $secret,
        protected ClockInterface $clock,
        protected int $ttl = 600,
    ) {
    }

    public function encode(array $payload): string
    {
        $payload[self::EXPIRY_KEY] = $this->clock->now()->getTimestamp() + $this->ttl;

        $body = $this->base64UrlEncode((string) json_encode($payload));

        return $body . self::SEPARATOR . $this->sign($body);
    }

    public function decode(string $raw): ?array
    {
        $separatorPosition = strrpos($raw, self::SEPARATOR);
        if ($separatorPosition === false) {
            return null;
        }

        $body = substr($raw, 0, $separatorPosition);
        $signature = substr($raw, $separatorPosition + 1);
        if ($body === '' || ! hash_equals($this->sign($body), $signature)) {
            return null;
        }

        $decoded = json_decode($this->base64UrlDecode($body), true);
        if (! is_array($decoded)) {
            return null;
        }

        // Fail closed on a missing or non-integer `exp`: a validly signed body without one is a
        // value minted before this check existed, and the whole point is that such a value must
        // stop working rather than keep its unlimited lifetime.
        $expiresAt = $decoded[self::EXPIRY_KEY] ?? null;
        if (! is_int($expiresAt) || $expiresAt <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        unset($decoded[self::EXPIRY_KEY]);

        return $decoded;
    }

    protected function sign(string $body): string
    {
        return hash_hmac('sha256', $body, $this->secret);
    }

    protected function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    protected function base64UrlDecode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
