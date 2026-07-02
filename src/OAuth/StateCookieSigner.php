<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

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
 */
class StateCookieSigner implements StateCookieSignerInterface
{
    protected const SEPARATOR = '.';

    public function __construct(
        protected string $secret,
    ) {
    }

    public function encode(array $payload): string
    {
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

        return is_array($decoded) ? $decoded : null;
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
