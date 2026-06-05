<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Passkey;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionPasskeyOptionsStorage implements SessionPasskeyOptionsStorageInterface
{
    protected const SESSION_KEY_PREFIX = 'three_brs.passkey.';

    public function __construct(
        protected RequestStack $requestStack,
    ) {
    }

    public function store(string $key, string $serialized): void
    {
        $this->session()->set($this->fullKey($key), $serialized);
    }

    public function consume(string $key): ?string
    {
        $session = $this->session();
        $stored = $session->get($this->fullKey($key));
        $session->remove($this->fullKey($key));

        return is_string($stored) ? $stored : null;
    }

    protected function session(): SessionInterface
    {
        return $this->requestStack->getSession();
    }

    protected function fullKey(string $key): string
    {
        return static::SESSION_KEY_PREFIX . $key;
    }
}
